#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt::{info, panic};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_futures::select::{select, select3, select_array, Either, Either3};
use embassy_futures::yield_now;
use embassy_rp::clocks::RoscRng;
use embassy_rp::gpio::{Input, Level, Output, Pin, Pull};
use embassy_rp::interrupt;
use embassy_rp::peripherals::USB;
use embassy_rp::spi::{Config as SpiConfig, Spi};
use embassy_rp::usb::Driver;
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use embassy_sync::pipe::{Pipe, Reader as PipeReader, Writer as PipeWriter};
use embassy_time::{Delay, Duration, Instant, Timer};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config as UsbConfig};
use embedded_hal_1 as eh1;
use embedded_hal_async as eha;
use embedded_hal_async::spi::ExclusiveDevice;
use embedded_io::asynch::Write;
use panic_probe as _;
use rand::RngCore;
use w5500_dhcp::{
    hl::{net::Eui48Addr, Tcp},
    ll::{
        aio::Registers,
        eh1::{reset as w5500_reset, vdm::W5500},
        SocketInterruptMask, Sn, SOCKETS,
    },
    Client as DhcpClient, Hostname,
};

pub mod binary_info;

const PACKET_SIZE: usize = 64;

const DEFAULT_MAC: Eui48Addr = Eui48Addr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00);
const DEFAULT_HOSTNAME_STR: &'static str = "rp2040";
const DEFAULT_HOSTNAME: Hostname<'static> = Hostname::new_unwrapped(DEFAULT_HOSTNAME_STR);

const DHCP_SOCKET: Sn = Sn::Sn7;

const DEFAULT_PORTS: [u16; 7] = [23, 0xC018, 0xC019, 0xC01A, 0xC01B, 0xC01C, 0xC01D];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum SocketState {
    Listening,
    Connected,
    Disconnected,
}

// TODO: handle errors better

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    info!("Hello there!");

    let p = embassy_rp::init(Default::default());

    info!("Initializing W5500");
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
    let w5500_int = Input::new(p.PIN_20, Pull::None);

    info!("Resetting W5500");
    let mut w5500_rst = Output::new(p.PIN_15, Level::High);
    w5500_reset(&mut w5500_rst, &mut Delay).unwrap();
    let w5500 = W5500::new(w5500_spi_dev);

    info!("Initializing USB device driver");
    // Create the driver, from the HAL.
    let irq = interrupt::take!(USBCTRL_IRQ);
    let driver = Driver::new(p.USB, irq);

    // Create embassy-usb Config
    let mut config = UsbConfig::new(0xc0de, 0xcafe);
    config.manufacturer = Some("yodal_");
    config.product = Some("RP2040 RFC2217 Adapter");
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

    let mut cdc_acm_state0 = State::new();
    let mut cdc_acm_state1 = State::new();
    // let mut cdc_acm_state2 = State::new();
    // let mut cdc_acm_state3 = State::new();
    // let mut cdc_acm_state4 = State::new();
    // let mut cdc_acm_state5 = State::new();
    // let mut cdc_acm_state6 = State::new();
    let mut builder = Builder::new(
        driver,
        config,
        &mut device_descriptor,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut control_buf,
        None,
    );
    info!("Initializing CDC ACM interfaces");
    let mut cdc_acm0 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state0, PACKET_SIZE as u16);
    let mut cdc_acm1 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state1, PACKET_SIZE as u16);
    // let mut cdc_acm2 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state2, PACKET_SIZE as u16);
    // let mut cdc_acm3 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state3, PACKET_SIZE as u16);
    // let mut cdc_acm4 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state4, PACKET_SIZE as u16);
    // let mut cdc_acm5 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state5, PACKET_SIZE as u16);
    // let mut cdc_acm6 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state6, PACKET_SIZE as u16);
    let mut usb = builder.build();

    info!("Initializing communication pipes");
    let usb_to_eth0 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let usb_to_eth1 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let usb_to_eth2 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let usb_to_eth3 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let usb_to_eth4 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let usb_to_eth5 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let usb_to_eth6 = Pipe::<CriticalSectionRawMutex, 256>::new();

    let eth_to_usb0 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let eth_to_usb1 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let eth_to_usb2 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let eth_to_usb3 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let eth_to_usb4 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let eth_to_usb5 = Pipe::<CriticalSectionRawMutex, 256>::new();
    let eth_to_usb6 = Pipe::<CriticalSectionRawMutex, 256>::new();

    // Run everything concurrently.
    info!("Running everything");
    join3(
        usb.run(),
        w5500_loop(
            w5500,
            w5500_int,
            [
                SocketPipes {
                    tx: usb_to_eth0.reader(),
                    rx: eth_to_usb0.writer(),
                },
                SocketPipes {
                    tx: usb_to_eth1.reader(),
                    rx: eth_to_usb1.writer(),
                },
                SocketPipes {
                    tx: usb_to_eth2.reader(),
                    rx: eth_to_usb2.writer(),
                },
                SocketPipes {
                    tx: usb_to_eth3.reader(),
                    rx: eth_to_usb3.writer(),
                },
                SocketPipes {
                    tx: usb_to_eth4.reader(),
                    rx: eth_to_usb4.writer(),
                },
                SocketPipes {
                    tx: usb_to_eth5.reader(),
                    rx: eth_to_usb5.writer(),
                },
                SocketPipes {
                    tx: usb_to_eth6.reader(),
                    rx: eth_to_usb6.writer(),
                },
            ],
        ),
        select_array([
            cdc_acm_loop(&mut cdc_acm0, &eth_to_usb0, usb_to_eth0.writer()),
            cdc_acm_loop(&mut cdc_acm1, &eth_to_usb1, usb_to_eth1.writer()),
            // cdc_acm_loop(&mut cdc_acm2, &eth_to_usb2, usb_to_eth2.writer()),
            // cdc_acm_loop(&mut cdc_acm3, &eth_to_usb3, usb_to_eth3.writer()),
            // cdc_acm_loop(&mut cdc_acm4, &eth_to_usb4, usb_to_eth4.writer()),
            // cdc_acm_loop(&mut cdc_acm5, &eth_to_usb5, usb_to_eth5.writer()),
            // cdc_acm_loop(&mut cdc_acm6, &eth_to_usb6, usb_to_eth6.writer()),
        ]),
    )
    .await;
}

struct SocketPipes<'r, 't, M: RawMutex, const RN: usize, const TN: usize> {
    rx: PipeWriter<'r, M, RN>,
    tx: PipeReader<'t, M, TN>,
}

impl<'r, 't, M: RawMutex, const TN: usize, const RN: usize> SocketPipes<'r, 't, M, RN, TN> {
    pub async fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        self.rx.write(buf).await
    }

    pub async fn write_all<'a>(&'a self, buf: &'a [u8]) {
        let total_bytes = buf.len();
        let mut total_written = 0;
        loop {
            total_written += self.write(buf).await;
            if total_written >= total_bytes {
                break;
            }
        }
    }

    pub async fn read<'a>(&'a self, buf: &'a mut [u8]) -> &'a [u8] {
        let bytes = self.tx.read(buf).await;
        &buf[..bytes]
    }
}

async fn w5500_loop<D, I, M: RawMutex, const RN: usize, const TN: usize>(
    mut w5500: W5500<D>,
    mut w5500_int: Input<'_, I>,
    socket_pipes: [SocketPipes<'_, '_, M, RN, TN>; 7],
) where
    D: eh1::spi::SpiDevice + eha::spi::SpiDevice,
    <D as eh1::spi::SpiDevice>::Bus: eh1::spi::SpiBusRead + eh1::spi::SpiBusWrite,
    <D as eha::spi::SpiDevice>::Bus: eha::spi::SpiBusRead + eha::spi::SpiBusWrite,
    I: Pin,
{
    let socket_ports = DEFAULT_PORTS;

    w5500
        .set_shar(&DEFAULT_MAC)
        .await
        .expect("failed to set MAC address");
    // Enable interrupts for socket
    // TODO: only enable sockets that are enabled
    w5500
        .set_simr(SOCKETS[..7].iter().fold(0, |acc, s| acc | s.bitmask()))
        .await
        .expect("failed to enable socket interrupts");
    for socket in &SOCKETS[..7] {
        w5500
            .set_sn_imr(*socket, SocketInterruptMask::DEFAULT.mask_sendok())
            .await
            .expect("failed to disabled SENDOK interrupt on socket");
    }

    let mut dhcp_client = DhcpClient::new(
        DHCP_SOCKET,
        RoscRng.next_u64(),
        DEFAULT_MAC,
        DEFAULT_HOSTNAME,
    );
    dhcp_client.setup_socket(&mut w5500).unwrap();

    loop {
        let mut dhcp_delay_secs = 0u32;

        let mut socket_state = [SocketState::Disconnected; 7];
        loop {
            for ((socket, state), port) in
                SOCKETS[..7].iter().zip(&mut socket_state).zip(socket_ports)
            {
                // TODO: don't listen on disabled sockets
                // TODO: stop listening on disabled sockets
                if *state == SocketState::Disconnected {
                    info!("socket listening: {}::{}", socket, port);
                    // TODO: maybe don't listen while we have no IP address
                    w5500.tcp_listen(*socket, port).unwrap();
                    *state = SocketState::Listening;
                }
            }

            match select3(
                w5500_int.wait_for_low(),
                Timer::after(Duration::from_secs(dhcp_delay_secs as u64)),
                select_array([
                    socket_pipes[0].read(&mut [0; PACKET_SIZE as usize]),
                    socket_pipes[1].read(&mut [0; PACKET_SIZE as usize]),
                    socket_pipes[2].read(&mut [0; PACKET_SIZE as usize]),
                    socket_pipes[3].read(&mut [0; PACKET_SIZE as usize]),
                    socket_pipes[4].read(&mut [0; PACKET_SIZE as usize]),
                    socket_pipes[5].read(&mut [0; PACKET_SIZE as usize]),
                    socket_pipes[6].read(&mut [0; PACKET_SIZE as usize]),
                ]),
            )
            .await
            {
                Either3::First(_) => {
                    // TODO: handle IR interrupts

                    let sir = w5500.sir().await.unwrap();
                    debug!("sir: 0x{:02X}", sir);

                    // DHCP interrupt handling
                    if sir & DHCP_SOCKET.bitmask() != 0 {
                        dhcp_delay_secs = dhcp_client
                            .process(
                                &mut w5500,
                                (Instant::now().as_secs() % (u32::MAX as u64)) as u32,
                            )
                            .unwrap();
                    }

                    // Telnet interrupt handling
                    for socket in SOCKETS[..7].iter().filter(|s| sir & s.bitmask() != 0) {
                        let sn_ir = w5500.sn_ir(*socket).await.unwrap();
                        debug!("{}: {}", socket, sn_ir);
                        if sn_ir.any_raised() {
                            w5500.set_sn_ir(*socket, sn_ir.into()).await.unwrap();
                        }

                        // TODO: if this socket is disabled, disconnect

                        if sn_ir.con_raised() {
                            info!("socket connected: {}", socket);
                            // TODO: maybe clear TX pipe
                            socket_state[usize::from(*socket)] = SocketState::Connected;
                        }
                        if sn_ir.discon_raised() {
                            info!("socket disconnected: {}", socket);
                            socket_state[usize::from(*socket)] = SocketState::Disconnected;
                        }
                        if sn_ir.timeout_raised() {
                            info!("socket timed out: {}", socket);
                            socket_state[usize::from(*socket)] = SocketState::Disconnected;
                        }
                        if sn_ir.recv_raised() {
                            let mut eth_buf = [0; PACKET_SIZE as usize];
                            let eth_bytes = w5500.tcp_read(*socket, &mut eth_buf).unwrap();

                            socket_pipes[usize::from(*socket)]
                                .write_all(&eth_buf[..eth_bytes as usize])
                                .await;
                        }
                    }
                }
                Either3::Second(_) => {
                    dhcp_delay_secs = dhcp_client
                        .process(
                            &mut w5500,
                            (Instant::now().as_secs() % (u32::MAX as u64)) as u32,
                        )
                        .unwrap();
                }
                Either3::Third((data, socket)) => {
                    if socket_state[socket] == SocketState::Connected {
                        let total_bytes = data.len();
                        let mut total_written = 0;
                        loop {
                            total_written += w5500
                                .tcp_write(SOCKETS[socket], &data[total_written..])
                                .unwrap() as usize;
                            if total_written >= total_bytes {
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
}

async fn cdc_acm_loop<'d, M: RawMutex, const TN: usize, const RN: usize>(
    cdc_acm: &mut CdcAcmClass<'d, Driver<'d, USB>>,
    usb_tx: &Pipe<M, TN>,
    mut usb_rx: PipeWriter<'_, M, RN>,
) {
    loop {
        // TODO: handle control signals
        let mut eth_buf = [0; PACKET_SIZE];
        let mut usb_buf = [0; PACKET_SIZE];

        // TODO: maybe clear usb_tx pipe on connect
        // TODO: check for line-coding changes
        let usb_read_fut = async {
            cdc_acm.wait_connection().await;
            cdc_acm.read_packet(&mut usb_buf).await
        };
        match select(usb_tx.read(&mut eth_buf), usb_read_fut).await {
            Either::First(eth_bytes) => {
                match cdc_acm.write_packet(&eth_buf[..eth_bytes]).await {
                    Ok(_) => {
                        // Send a zero length packet if there is nothing else in the pipe and
                        // the last packet was a full packet.
                        if usb_tx.is_empty() && eth_bytes == PACKET_SIZE {
                            match cdc_acm.write_packet(&[]).await {
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
                usb_rx.write_all(data).await.unwrap();
            }
            Either::Second(Err(EndpointError::Disabled)) => {}
            Either::Second(Err(EndpointError::BufferOverflow)) => panic!("Buffer overflow"),
        }
    }
}
