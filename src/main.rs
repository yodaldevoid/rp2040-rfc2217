#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt::{info, panic};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_futures::select::{select, Either};
use embassy_futures::yield_now;
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::interrupt;
use embassy_rp::spi::{Config as SpiConfig, Spi};
use embassy_rp::usb::Driver;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::pipe::Pipe;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config as UsbConfig};
use embedded_hal_async::spi::ExclusiveDevice;
use embedded_io::asynch::Write;
use panic_probe as _;
use w5500_dhcp::{
    hl::{
        net::{Eui48Addr, Ipv4Addr},
        Tcp,
    },
    ll::{aio::Registers, eh1::vdm::W5500, Sn},
};

pub mod binary_info;

const PACKET_SIZE: usize = 64;

const DEFAULT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const DEFAULT_SUBNET: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const DEFAULT_GATEWAY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const DEFAULT_MAC: Eui48Addr = Eui48Addr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00);

const TELNET_SOCKET: Sn = Sn::Sn1;
const TELNET_PORT: u16 = 23;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum SocketState {
    Listening,
    Connected,
    Disconnected,
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    info!("Hello there!");

    let p = embassy_rp::init(Default::default());

    let miso = p.PIN_16;
    let mosi = p.PIN_19;
    let clk = p.PIN_18;
    let spi0 = Spi::new(
        p.SPI0,
        clk,
        mosi,
        miso,
        p.DMA_CH0,
        p.DMA_CH1,
        SpiConfig::default(),
    );
    let cs = Output::new(p.PIN_17, Level::High);
    let w5500_spi_dev = ExclusiveDevice::new(spi0, cs);
    let mut w5500_int = Input::new(p.PIN_20, Pull::None);

    // TODO: reset W5500
    let mut w5500 = W5500::new(w5500_spi_dev);

    w5500
        .set_shar(&DEFAULT_MAC)
        .await
        .expect("failed to set MAC address");
    w5500
        .set_sipr(&DEFAULT_IP)
        .await
        .expect("failed to set IP address");
    w5500
        .set_gar(&DEFAULT_GATEWAY)
        .await
        .expect("failed to set gateway");
    w5500
        .set_subr(&DEFAULT_SUBNET)
        .await
        .expect("failed to set subnet mask");
    // Enable interrupts for socket
    w5500
        .set_simr(TELNET_SOCKET.bitmask())
        .await
        .expect("failed to enable socket interrupts");

    // Create the driver, from the HAL.
    let irq = interrupt::take!(USBCTRL_IRQ);
    let driver = Driver::new(p.USB, irq);

    // Create embassy-usb Config
    let mut config = UsbConfig::new(0xc0de, 0xcafe);
    config.manufacturer = Some("Embassy");
    config.product = Some("USB-serial example");
    config.serial_number = Some("12345678");
    config.max_power = 100;
    config.max_packet_size_0 = PACKET_SIZE as u8;

    // Required for windows compatiblity.
    // https://developer.nordicsemi.com/nRF_Connect_SDK/doc/1.9.1/kconfig/CONFIG_CDC_ACM_IAD.html#help
    config.device_class = 0xEF;
    config.device_sub_class = 0x02;
    config.device_protocol = 0x01;
    config.composite_with_iads = true;

    // Create embassy-usb DeviceBuilder using the driver and config.
    // It needs some buffers for building the descriptors.
    let mut device_descriptor = [0; 256];
    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 64];

    let mut state = State::new();
    let mut builder = Builder::new(
        driver,
        config,
        &mut device_descriptor,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut control_buf,
        None,
    );
    let mut class = CdcAcmClass::new(&mut builder, &mut state, PACKET_SIZE as u16);
    let mut usb = builder.build();
    let usb_fut = usb.run();

    let usb_to_eth = Pipe::<CriticalSectionRawMutex, 265>::new();
    let mut usb_to_eth_writer = usb_to_eth.writer();
    let eth_to_usb = Pipe::<CriticalSectionRawMutex, 265>::new();
    let mut eth_to_usb_writer = eth_to_usb.writer();

    let w5500_fut = async {
        loop {
            w5500.tcp_listen(TELNET_SOCKET, TELNET_PORT).unwrap();
            let mut socket_state = SocketState::Listening;
            while socket_state != SocketState::Disconnected {
                let mut usb_buf = [0; PACKET_SIZE as usize];
                match select(w5500_int.wait_for_low(), usb_to_eth.read(&mut usb_buf)).await {
                    Either::First(_) => {
                        // TODO: handle IR interrupts

                        // TODO: check SIR for source of socket interrupts

                        let sn_ir = w5500.sn_ir(TELNET_SOCKET).await.unwrap();
                        if sn_ir.any_raised() {
                            w5500.set_sn_ir(TELNET_SOCKET, sn_ir.into()).await.unwrap();
                        }

                        if sn_ir.con_raised() {
                            // TODO: maybe clear usb_to_eth pipe
                            socket_state = SocketState::Connected;
                        }
                        if sn_ir.recv_raised() {
                            w5500.set_sn_ir(TELNET_SOCKET, sn_ir.into()).await.unwrap();
                            let mut eth_buf = [0; PACKET_SIZE as usize];
                            let eth_bytes = w5500.tcp_read(TELNET_SOCKET, &mut eth_buf).unwrap();

                            eth_to_usb_writer
                                .write_all(&eth_buf[..eth_bytes as usize])
                                .await
                                .unwrap();
                        }
                        if sn_ir.discon_raised() {
                            info!("socket disconnected");
                            socket_state = SocketState::Disconnected;
                        }
                        if sn_ir.timeout_raised() {
                            info!("socket timed out");
                            socket_state = SocketState::Disconnected;
                        }
                    }
                    Either::Second(usb_bytes) => {
                        if socket_state == SocketState::Connected {
                            let mut total_bytes_written = 0;
                            loop {
                                let data = &mut usb_buf[total_bytes_written..usb_bytes];
                                let bytes_written = w5500.tcp_write(TELNET_SOCKET, data).unwrap();
                                total_bytes_written += bytes_written as usize;
                                if total_bytes_written >= usb_bytes {
                                    break;
                                }
                                yield_now().await;
                            }
                        }
                    }
                }

                yield_now().await;
            }
        }
    };

    let cdc_acm_fut = async {
        loop {
            // TODO: handle control signals
            let mut eth_buf = [0; PACKET_SIZE];
            let mut usb_buf = [0; PACKET_SIZE];

            // TODO: maybe clear eth_to_usb pipe on connect
            let usb_read_fut = async {
                class.wait_connection().await;
                class.read_packet(&mut usb_buf).await
            };
            match select(eth_to_usb.read(&mut eth_buf), usb_read_fut).await {
                Either::First(eth_bytes) => {
                    match class.write_packet(&eth_buf[..eth_bytes]).await {
                        Ok(_) => {
                            // Send a zero length packet if there is nothing else in the pipe and
                            // the last packet was a full packet.
                            if eth_to_usb.is_empty() && eth_bytes == PACKET_SIZE {
                                match class.write_packet(&[]).await {
                                    Ok(_) => {}
                                    Err(EndpointError::Disabled) => {}
                                    Err(EndpointError::BufferOverflow) => panic!("Buffer overflow"),
                                }
                            }
                        }
                        Err(EndpointError::Disabled) => {}
                        Err(EndpointError::BufferOverflow) => panic!("Buffer overflow"),
                    }
                }
                Either::Second(Ok(usb_bytes)) => {
                    let data = &usb_buf[..usb_bytes];
                    usb_to_eth_writer.write_all(data).await.unwrap();
                }
                Either::Second(Err(EndpointError::Disabled)) => {}
                Either::Second(Err(EndpointError::BufferOverflow)) => panic!("Buffer overflow"),
            }
        }
    };

    // Run everything concurrently.
    join3(usb_fut, w5500_fut, cdc_acm_fut).await;
}
