#![no_std]
#![no_main]
#![feature(type_alias_impl_trait, async_fn_in_trait, async_closure)]
#![allow(incomplete_features)]

use defmt::{debug, info, panic};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::{
    join::join3,
    select::{select, select3, select_array, Either, Either3},
    yield_now,
};
use embassy_rp::{
    clocks::RoscRng,
    gpio::{Input, Level, Output, Pin, Pull},
    interrupt,
    peripherals::USB,
    spi::{Config as SpiConfig, Spi},
    usb::Driver,
};
use embassy_sync::{
    blocking_mutex::raw::{NoopRawMutex, RawMutex},
    mutex::Mutex,
};
use embassy_time::{Delay, Duration, Instant, Timer};
use embassy_usb::{
    class::cdc_acm::{CdcAcmClass, State},
    driver::EndpointError,
    {Builder, Config as UsbConfig},
};
use embedded_hal_1 as eh1;
use embedded_hal_async::{self as eha, spi::ExclusiveDevice};
use embedded_io::{
    asynch::{Read, Write},
    Io,
};
use panic_probe as _;
use rand::RngCore;
use w5500_dhcp::{
    hl::{net::Eui48Addr, Tcp},
    ll::{
        aio::Registers,
        eh1::{reset as w5500_reset, vdm::W5500},
        Sn, SocketInterruptMask, SOCKETS,
    },
    Client as DhcpClient, Hostname,
};

pub mod binary_info;
mod telnet;

const PACKET_SIZE: usize = 64;

// TODO: handle errors better

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    info!("Hello there!");

    let p = embassy_rp::init(Default::default());

    info!("Initializing W5500");
    let miso = p.PIN_16;
    let mosi = p.PIN_19;
    let clk = p.PIN_18;
    let mut config = SpiConfig::default();
    config.frequency = 30_000_000;
    let spi0 = Spi::new(p.SPI0, clk, mosi, miso, p.DMA_CH0, p.DMA_CH1, config);
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
    let mut device_descriptor = [0; 512];
    let mut config_descriptor = [0; 512];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 64];

    let mut cdc_acm_state0 = State::new();
    let mut cdc_acm_state1 = State::new();
    let mut cdc_acm_state2 = State::new();
    let mut cdc_acm_state3 = State::new();
    let mut cdc_acm_state4 = State::new();
    let mut cdc_acm_state5 = State::new();
    let mut cdc_acm_state6 = State::new();
    let mut builder = Builder::<'_, _, 16>::new(
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
    let mut cdc_acm2 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state2, PACKET_SIZE as u16);
    let mut cdc_acm3 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state3, PACKET_SIZE as u16);
    let mut cdc_acm4 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state4, PACKET_SIZE as u16);
    let mut cdc_acm5 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state5, PACKET_SIZE as u16);
    let mut cdc_acm6 = CdcAcmClass::new(&mut builder, &mut cdc_acm_state6, PACKET_SIZE as u16);
    let mut usb = builder.build();

    info!("Initializing telnet codecs");
    let telnet_codec0 = telnet::Codec::<NoopRawMutex>::new();
    let telnet_codec1 = telnet::Codec::<NoopRawMutex>::new();
    let telnet_codec2 = telnet::Codec::<NoopRawMutex>::new();
    let telnet_codec3 = telnet::Codec::<NoopRawMutex>::new();
    let telnet_codec4 = telnet::Codec::<NoopRawMutex>::new();
    let telnet_codec5 = telnet::Codec::<NoopRawMutex>::new();
    let telnet_codec6 = telnet::Codec::<NoopRawMutex>::new();

    // Run everything concurrently.
    info!("Running everything");
    join3(
        usb.run(),
        w5500_loop(
            w5500,
            w5500_int,
            [
                &telnet_codec0,
                &telnet_codec1,
                &telnet_codec2,
                &telnet_codec3,
                &telnet_codec4,
                &telnet_codec5,
                &telnet_codec6,
            ],
        ),
        select_array([
            cdc_acm_loop(
                &mut cdc_acm0,
                telnet_codec0.data_sender(),
                telnet_codec0.data_receiver(),
            ),
            cdc_acm_loop(
                &mut cdc_acm1,
                telnet_codec1.data_sender(),
                telnet_codec1.data_receiver(),
            ),
            cdc_acm_loop(
                &mut cdc_acm2,
                telnet_codec2.data_sender(),
                telnet_codec2.data_receiver(),
            ),
            cdc_acm_loop(
                &mut cdc_acm3,
                telnet_codec3.data_sender(),
                telnet_codec3.data_receiver(),
            ),
            cdc_acm_loop(
                &mut cdc_acm4,
                telnet_codec4.data_sender(),
                telnet_codec4.data_receiver(),
            ),
            cdc_acm_loop(
                &mut cdc_acm5,
                telnet_codec5.data_sender(),
                telnet_codec5.data_receiver(),
            ),
            cdc_acm_loop(
                &mut cdc_acm6,
                telnet_codec6.data_sender(),
                telnet_codec6.data_receiver(),
            ),
        ]),
    )
    .await;
}

const DEFAULT_MAC: Eui48Addr = Eui48Addr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00);
const DEFAULT_HOSTNAME_STR: &'static str = "rp2040";
const DEFAULT_HOSTNAME: Hostname<'static> = Hostname::new_unwrapped(DEFAULT_HOSTNAME_STR);

const DHCP_SOCKET: Sn = Sn::Sn7;

const DEFAULT_PORTS: [u16; 7] = [23, 0xC018, 0xC019, 0xC01A, 0xC01B, 0xC01C, 0xC01D];

#[derive(Debug, defmt::Format, Copy, Clone, PartialEq, Eq)]
enum SocketState {
    Listening,
    Connected,
    Disconnected,
}

#[derive(Debug, defmt::Format)]
struct WriteSocketError<E: core::fmt::Debug>(E);

impl<E: core::fmt::Debug> embedded_io::Error for WriteSocketError<E> {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

struct WriteSocket<'a, M, D>
where
    M: RawMutex,
    D: eh1::spi::SpiDevice + eha::spi::SpiDevice,
    <D as eh1::spi::SpiDevice>::Bus: eh1::spi::SpiBusRead + eh1::spi::SpiBusWrite,
    <D as eha::spi::SpiDevice>::Bus: eha::spi::SpiBusRead + eha::spi::SpiBusWrite,
{
    state: &'a Mutex<M, SocketState>,
    socket: Sn,
    w5500: &'a Mutex<M, W5500<D>>,
}

impl<'a, M, D> Io for WriteSocket<'a, M, D>
where
    M: RawMutex,
    D: eh1::spi::SpiDevice + eha::spi::SpiDevice,
    <D as eh1::spi::SpiDevice>::Bus: eh1::spi::SpiBusRead + eh1::spi::SpiBusWrite,
    <D as eha::spi::SpiDevice>::Bus: eha::spi::SpiBusRead + eha::spi::SpiBusWrite,
{
    type Error = WriteSocketError<<D as eha::spi::ErrorType>::Error>;
}

impl<'a, M, D> Write for WriteSocket<'a, M, D>
where
    M: RawMutex,
    D: eh1::spi::SpiDevice + eha::spi::SpiDevice,
    <D as eh1::spi::SpiDevice>::Bus: eh1::spi::SpiBusRead + eh1::spi::SpiBusWrite,
    <D as eha::spi::SpiDevice>::Bus: eha::spi::SpiBusRead + eha::spi::SpiBusWrite,
{
    async fn write(
        &mut self,
        buf: &[u8],
    ) -> Result<usize, WriteSocketError<<D as eha::spi::ErrorType>::Error>> {
        let state = self.state.lock().await.clone();
        if state == SocketState::Connected {
            // TODO: Return the error
            Ok(self
                .w5500
                .lock()
                .await
                .tcp_write(self.socket, buf)
                .map(usize::from)
                .unwrap())
        } else {
            Ok(buf.len())
        }
    }
}

// TODO: TELNET Synch
async fn w5500_loop<D, I, M: RawMutex>(
    mut w5500: W5500<D>,
    mut w5500_int: Input<'_, I>,
    codec: [&telnet::Codec<M>; 7],
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

    let mut w5500 = Mutex::<NoopRawMutex, _>::new(w5500);
    let mut socket_state = [
        Mutex::<NoopRawMutex, _>::new(SocketState::Disconnected),
        Mutex::<NoopRawMutex, _>::new(SocketState::Disconnected),
        Mutex::<NoopRawMutex, _>::new(SocketState::Disconnected),
        Mutex::<NoopRawMutex, _>::new(SocketState::Disconnected),
        Mutex::<NoopRawMutex, _>::new(SocketState::Disconnected),
        Mutex::<NoopRawMutex, _>::new(SocketState::Disconnected),
        Mutex::<NoopRawMutex, _>::new(SocketState::Disconnected),
    ];

    let mut dhcp_delay_secs = 0u32;
    loop {
        for ((socket, state), port) in SOCKETS[..7].iter().zip(&mut socket_state).zip(socket_ports)
        {
            let state = state.get_mut();
            // TODO: don't listen on disabled sockets
            // TODO: stop listening on disabled sockets
            if *state == SocketState::Disconnected {
                info!("socket listening: {}::{}", socket, port);
                // TODO: maybe don't listen while we have no IP address
                w5500.get_mut().tcp_listen(*socket, port).unwrap();
                *state = SocketState::Listening;
            }
        }

        let write_socket = |socket| WriteSocket {
            state: &socket_state[socket],
            socket: SOCKETS[socket],
            w5500: &w5500,
        };
        match select3(
            w5500_int.wait_for_low(),
            Timer::after(Duration::from_secs(dhcp_delay_secs as u64)),
            select_array([
                codec[0].encode(&mut write_socket(0)),
                codec[1].encode(&mut write_socket(1)),
                codec[2].encode(&mut write_socket(2)),
                codec[3].encode(&mut write_socket(3)),
                codec[4].encode(&mut write_socket(4)),
                codec[5].encode(&mut write_socket(5)),
                codec[6].encode(&mut write_socket(6)),
            ]),
        )
        .await
        {
            Either3::First(_) => {
                let mut w5500 = w5500.lock().await;

                // TODO: handle IR interrupts

                let sir = w5500.sir().await.unwrap();
                debug!("sir: 0x{=u8:02X}", sir);

                // DHCP interrupt handling
                if sir & DHCP_SOCKET.bitmask() != 0 {
                    dhcp_delay_secs = dhcp_client
                        .process(
                            &mut *w5500,
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

                    let sn = usize::from(*socket);
                    let mut state = socket_state[sn].lock().await;
                    if sn_ir.con_raised() {
                        info!("socket connected: {}", socket);
                        // TODO: maybe clear TX pipe
                        codec[sn].init().await;
                        *state = SocketState::Connected;
                    }
                    if sn_ir.discon_raised() {
                        info!("socket disconnected: {}", socket);
                        codec[sn].reset().await;
                        *state = SocketState::Disconnected;
                    }
                    if sn_ir.timeout_raised() {
                        info!("socket timed out: {}", socket);
                        codec[sn].reset().await;
                        *state = SocketState::Disconnected;
                    }
                    if sn_ir.recv_raised() {
                        codec[sn]
                            .decode(|buf| w5500.tcp_read(*socket, buf).map(usize::from))
                            .await
                            .unwrap();
                    }
                }
            }
            Either3::Second(_) => {
                dhcp_delay_secs = dhcp_client
                    .process(
                        &mut *w5500.lock().await,
                        (Instant::now().as_secs() % (u32::MAX as u64)) as u32,
                    )
                    .unwrap();
            }
            Either3::Third(_) => {}
        }

        yield_now().await;
    }
}

async fn cdc_acm_loop<'d, M: RawMutex>(
    cdc_acm: &mut CdcAcmClass<'d, Driver<'d, USB>>,
    mut usb_tx: telnet::DataSender<'_, M>,
    mut usb_rx: telnet::DataReceiver<'_, M>,
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
                let eth_bytes = eth_bytes.unwrap();
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
