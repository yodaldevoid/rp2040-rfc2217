use core::fmt::{Arguments, Debug};

use defmt::{info, panic, trace, unreachable};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::{
    flash::{Flash, ERASE_SIZE, FLASH_BASE},
    interrupt::USBCTRL_IRQ,
    peripherals::USB,
    usb::Driver,
    Peripherals,
};
use embassy_usb::{
    class::cdc_acm::{CdcAcmClass, State},
    driver::EndpointError,
    {Builder, Config as UsbConfig},
};
use embedded_io::blocking::Write;
use embedded_storage::{nor_flash::RmwMultiwriteNorFlashStorage, ReadStorage, Storage};
use nom::{
    branch::alt,
    bytes::{
        complete::tag,
        streaming::{tag_no_case, take_till, take_while},
    },
    character::{
        is_alphanumeric,
        streaming::{self, space0, space1},
    },
    combinator::verify,
    sequence::{preceded, terminated, tuple},
    IResult, Parser,
};
use panic_probe as _;
use w5500_dhcp::{
    hl::net::{Eui48Addr, Ipv4Addr, SocketAddrV4},
    Hostname,
};

use crate::PACKET_SIZE;

const FLASH_SIZE: usize = 2 * 1024 * 1024;
const CONFIG_DESC_SIZE: usize = 64;
const CONFIG_STR_SIZE: usize = 252;
const HOSTNAME_SIZE: usize = 253;
const HOSTNAME_LABEL_SIZE: usize = 633;

#[derive(Debug, defmt::Format, Clone)]
pub struct ProgramConfig {
    // USB Settings
    pub vid: u16,
    pub pid: u16,
    manufacturer_len: u8,
    manufacturer_bytes: [u8; CONFIG_STR_SIZE],
    product_len: u8,
    product_bytes: [u8; CONFIG_STR_SIZE],
    serial_number_len: u8,
    serial_number_bytes: [u8; CONFIG_STR_SIZE],

    // Ethernet settings
    pub mac: Eui48Addr,
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    hostname_len: u8,
    hostname_bytes: [u8; HOSTNAME_SIZE],
    pub ports: [SocketAddrV4; 7],
}

impl ProgramConfig {
    const fn new(
        vid: u16,
        pid: u16,
        manufacturer: &str,
        product: &str,
        serial_number: &str,
        mac: Eui48Addr,
        ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        hostname: Hostname<'_>,
        ports: [SocketAddrV4; 7],
    ) -> Self {
        let manufacturer = manufacturer.as_bytes();
        assert!(manufacturer.len() < CONFIG_STR_SIZE);
        let product = product.as_bytes();
        assert!(product.len() < CONFIG_STR_SIZE);
        let serial_number = serial_number.as_bytes();
        assert!(serial_number.len() < CONFIG_STR_SIZE);
        let hostname = hostname.as_bytes();
        assert!(hostname.len() < HOSTNAME_SIZE);

        let mut manufacturer_bytes = [0; CONFIG_STR_SIZE];
        let mut i = 0;
        while i < manufacturer_bytes.len() && i < manufacturer.len() {
            manufacturer_bytes[i] = manufacturer[i];
            i += 1;
        }
        let mut product_bytes = [0; CONFIG_STR_SIZE];
        let mut i = 0;
        while i < product_bytes.len() && i < product.len() {
            product_bytes[i] = product[i];
            i += 1;
        }
        let mut serial_number_bytes = [0; CONFIG_STR_SIZE];
        let mut i = 0;
        while i < serial_number_bytes.len() && i < serial_number.len() {
            serial_number_bytes[i] = serial_number[i];
            i += 1;
        }
        let mut hostname_bytes = [0; HOSTNAME_SIZE];
        let mut i = 0;
        while i < hostname_bytes.len() && i < hostname.len() {
            hostname_bytes[i] = hostname[i];
            i += 1;
        }

        Self {
            vid,
            pid,
            manufacturer_len: manufacturer.len() as u8,
            manufacturer_bytes,
            product_len: product.len() as u8,
            product_bytes,
            serial_number_len: serial_number.len() as u8,
            serial_number_bytes,
            mac,
            ip,
            subnet_mask,
            gateway_ip,
            hostname_len: hostname.len() as u8,
            hostname_bytes,
            ports,
        }
    }

    pub fn manufacturer(&self) -> Option<&str> {
        let bytes = &self.manufacturer_bytes;
        let len = self.manufacturer_len as usize;
        if len == 0 {
            None
        } else {
            core::str::from_utf8(&bytes[..len]).ok()
        }
    }

    fn set_manufacturer(&mut self, manufacturer: Option<&str>) {
        if let Some(manufacturer) = manufacturer {
            let bytes = manufacturer.as_bytes();
            let len = bytes.len().min(self.manufacturer_bytes.len());
            self.manufacturer_bytes[..len].copy_from_slice(&bytes[..len]);
            self.manufacturer_len = len as u8;
        } else {
            self.manufacturer_len = 0;
        }
    }

    pub fn product(&self) -> Option<&str> {
        let bytes = &self.product_bytes;
        let len = self.product_len as usize;
        if len == 0 {
            None
        } else {
            core::str::from_utf8(&bytes[..len]).ok()
        }
    }

    fn set_product(&mut self, product: Option<&str>) {
        if let Some(product) = product {
            let bytes = product.as_bytes();
            let len = bytes.len().min(self.product_bytes.len());
            self.product_bytes[..len].copy_from_slice(&bytes[..len]);
            self.product_len = len as u8;
        } else {
            self.product_len = 0;
        }
    }

    pub fn serial_number(&self) -> Option<&str> {
        let bytes = &self.serial_number_bytes;
        let len = self.serial_number_len as usize;
        if len == 0 {
            None
        } else {
            core::str::from_utf8(&bytes[..len]).ok()
        }
    }

    fn set_serial_number(&mut self, serial_number: Option<&str>) {
        if let Some(serial_number) = serial_number {
            let bytes = serial_number.as_bytes();
            let len = bytes.len().min(self.serial_number_bytes.len());
            self.serial_number_bytes[..len].copy_from_slice(&bytes[..len]);
            self.serial_number_len = len as u8;
        } else {
            self.serial_number_len = 0;
        }
    }

    pub fn hostname(&self) -> Hostname<'_> {
        let bytes = &self.hostname_bytes;
        let len = self.hostname_len as usize;
        Hostname::new_unwrapped(core::str::from_utf8(&bytes[..len]).unwrap_or(""))
    }

    fn set_hostname(&mut self, hostname: Hostname<'_>) {
        let bytes = hostname.as_bytes();
        let len = bytes.len().min(self.hostname_bytes.len());
        self.hostname_bytes[..len].copy_from_slice(&bytes[..len]);
        self.hostname_len = len as u8;
    }
}

pub static PROGRAM_CONFIG: ProgramConfig = ProgramConfig::new(
    0xC0DE,
    0xCAFE,
    "yodal_",
    "RP2040 RFC2217 Adapter",
    "12345678",
    Eui48Addr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00),
    Ipv4Addr::UNSPECIFIED,
    Ipv4Addr::UNSPECIFIED,
    Ipv4Addr::UNSPECIFIED,
    Hostname::new_unwrapped("rp2040"),
    [
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 23),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    ],
);

fn write_program_config<E>(
    flash: &mut impl Storage<Error = E>,
    config: &ProgramConfig,
) -> Result<(), E> {
    let buf = unsafe {
        ::core::slice::from_raw_parts(
            (config as *const ProgramConfig) as *const u8,
            ::core::mem::size_of::<ProgramConfig>(),
        )
    };

    let addr = ::core::ptr::addr_of!(PROGRAM_CONFIG) as usize;
    flash.write(addr.saturating_sub(FLASH_BASE) as u32, buf)
}

struct UsbWriter<'a, 'd, const N: usize> {
    usb: &'a mut CdcAcmClass<'d, Driver<'d, USB>>,
    buf: [u8; N],
    buf_len: usize,
}

impl<'a, 'd, const N: usize> UsbWriter<'a, 'd, N> {
    fn new(usb: &'a mut CdcAcmClass<'d, Driver<'d, USB>>) -> Self {
        Self {
            usb,
            buf: [0; N],
            buf_len: 0,
        }
    }

    async fn write(&mut self, bytes: &[u8]) {
        let rest = {
            let mut buf = &mut self.buf[self.buf_len..];
            buf.write_all(bytes).unwrap();
            buf.len()
        };
        self.buf_len = N - rest;
        self.write_packets().await;
    }

    async fn write_fmt(&mut self, fmt: Arguments<'_>) {
        let rest = {
            let mut buf = &mut self.buf[self.buf_len..];
            buf.write_fmt(fmt).unwrap();
            buf.len()
        };
        self.buf_len = N - rest;
        self.write_packets().await;
    }

    async fn write_packets(&mut self) {
        let mut written = 0;
        {
            let mut buf = &self.buf[..self.buf_len];
            while buf.len() >= PACKET_SIZE {
                match self.usb.write_packet(&buf[..PACKET_SIZE]).await {
                    Ok(_) => {}
                    Err(EndpointError::Disabled) => {}
                    Err(EndpointError::BufferOverflow) => panic!("Buffer overflow"),
                }

                buf = &buf[PACKET_SIZE..];
                written += PACKET_SIZE;
            }
        }
        self.buf.copy_within(written..self.buf_len, 0);
        self.buf_len -= written;
    }

    async fn finalize(mut self) {
        self.write_packets().await;
        match self.usb.write_packet(&self.buf[..self.buf_len]).await {
            Ok(_) => {}
            Err(EndpointError::Disabled) => {}
            Err(EndpointError::BufferOverflow) => panic!("Buffer overflow"),
        }
    }
}

pub async fn run(_spawner: Spawner, p: Peripherals, irq: USBCTRL_IRQ) {
    info!("Control interface selected");

    info!("Initializing USB device driver");
    // Create the driver, from the HAL.
    let driver = Driver::new(p.USB, irq);

    // Create embassy-usb Config
    let mut config = UsbConfig::new(PROGRAM_CONFIG.vid, PROGRAM_CONFIG.pid);
    config.manufacturer = PROGRAM_CONFIG.manufacturer();
    config.product = PROGRAM_CONFIG.product();
    config.serial_number = PROGRAM_CONFIG.serial_number();
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
    let mut control_buf = [0; CONFIG_DESC_SIZE];

    let mut cdc_acm_state = State::new();
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
    let mut cdc_acm = CdcAcmClass::new(&mut builder, &mut cdc_acm_state, PACKET_SIZE as u16);
    let mut usb = builder.build();

    let flash = Flash::<'_, _, FLASH_SIZE>::new(p.FLASH);
    let mut merge_buffer = [0; ERASE_SIZE];
    let mut flash = RmwMultiwriteNorFlashStorage::new(flash, &mut merge_buffer);

    async fn control_loop<'d, S>(cdc_acm: &mut CdcAcmClass<'d, Driver<'d, USB>>, flash: &mut S)
    where
        S: Storage,
        <S as ReadStorage>::Error: Debug,
    {
        let mut config = PROGRAM_CONFIG.clone();
        let mut buf = [0; 256];
        let mut buf_len = 0;

        // TODO: print new prompt on connection

        loop {
            let usb_read_fut = async {
                cdc_acm.wait_connection().await;
                cdc_acm.read_packet(&mut buf[buf_len..]).await
            };
            match usb_read_fut.await {
                Ok(bytes) => {
                    let old_len = buf_len;
                    buf_len += bytes;

                    // Remove leading backspaces/deletes so we don't delete the prompt.
                    let leading_bs = buf[..buf_len]
                        .iter()
                        .take_while(|b| b'\x08'.eq(b) || b'\x7F'.eq(b))
                        .count();
                    buf.copy_within(leading_bs..buf_len, 0);
                    buf_len -= leading_bs;

                    // Echo what was sent to us, inserting "\r\n" for each '\r' or '\n', removing
                    // duplicates.
                    // TODO: replace '\x08' with "\x08 \x08", probably the same with \x7F
                    {
                        let mut buf = &buf[old_len..buf_len];
                        let mut writer = UsbWriter::<'_, '_, 128>::new(cdc_acm);
                        while !buf.is_empty() {
                            let idx = if let Some(idx) =
                                buf.iter().position(|b| b'\r'.eq(b) || b'\n'.eq(b))
                            {
                                writer.write(&buf[..idx]).await;
                                writer.write(b"\r\n").await;
                                idx + buf[idx..]
                                    .iter()
                                    .take_while(|b| b'\r'.eq(b) || b'\n'.eq(b))
                                    .count()
                            } else {
                                writer.write(buf).await;
                                buf.len()
                            };
                            buf = &buf[idx..];
                        }
                        writer.finalize().await;
                    }

                    // Handle backspaces in the middle of the buffer.
                    while let Some(idx) = buf[..buf_len]
                        .iter()
                        .position(|b| b'\x08'.eq(b) || b'\x7F'.eq(b))
                    {
                        buf.copy_within((idx + 1)..buf_len, (idx - 1).max(0));
                        buf_len -= 2;
                    }

                    loop {
                        // TODO: keep track of last Incomplete and only try parsing when we have that much.
                        let used = if let Ok((rest, event)) = Command::parse(&buf[..buf_len]) {
                            let mut writer = UsbWriter::<'_, '_, 384>::new(cdc_acm);

                            match event {
                                Command::Help => {
                                    writer.write_fmt(format_args!("{}", HELP_TEXT)).await;
                                }
                                Command::List => {
                                    writer.write_fmt(format_args!("Legend:\r\n")).await;
                                    writer
                                        .write_fmt(format_args!("- Current [Saved]\r\n"))
                                        .await;
                                    writer
                                        .write_fmt(format_args!("* Modified [Saved]\r\n"))
                                        .await;
                                    writer
                                        .write_fmt(format_args!("\r\nUSB Settings:\r\n"))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} VID: 0x{:04X} [0x{:04X}]\r\n",
                                            if config.vid == PROGRAM_CONFIG.vid {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.vid,
                                            PROGRAM_CONFIG.vid,
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} PID: 0x{:04X} [0x{:04X}]\r\n",
                                            if config.pid == PROGRAM_CONFIG.pid {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.pid,
                                            PROGRAM_CONFIG.pid,
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} Manufacturer: \"{}\" [\"{}\"]\r\n",
                                            if config.manufacturer()
                                                == PROGRAM_CONFIG.manufacturer()
                                            {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.manufacturer().unwrap_or(""),
                                            PROGRAM_CONFIG.manufacturer().unwrap_or(""),
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} Product: \"{}\" [\"{}\"]\r\n",
                                            if config.product() == PROGRAM_CONFIG.product() {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.product().unwrap_or(""),
                                            PROGRAM_CONFIG.product().unwrap_or(""),
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} Serial Number: \"{}\" [\"{}\"]\r\n",
                                            if config.serial_number()
                                                == PROGRAM_CONFIG.serial_number()
                                            {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.serial_number().unwrap_or(""),
                                            PROGRAM_CONFIG.serial_number().unwrap_or(""),
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!("\r\nEthernet Settings:\r\n"))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} MAC: {} [{}]\r\n",
                                            if config.mac == PROGRAM_CONFIG.mac {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.mac,
                                            PROGRAM_CONFIG.mac,
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} IP: {} [{}]\r\n",
                                            if config.ip == PROGRAM_CONFIG.ip {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.ip,
                                            PROGRAM_CONFIG.ip,
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} Subnet Mask: {} [{}]\r\n",
                                            if config.subnet_mask == PROGRAM_CONFIG.subnet_mask {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.subnet_mask,
                                            PROGRAM_CONFIG.subnet_mask,
                                        ))
                                        .await;
                                    writer
                                        .write_fmt(format_args!(
                                            "{} Gateway: {} [{}]\r\n",
                                            if config.gateway_ip == PROGRAM_CONFIG.gateway_ip {
                                                '-'
                                            } else {
                                                '*'
                                            },
                                            config.gateway_ip,
                                            PROGRAM_CONFIG.gateway_ip,
                                        ))
                                        .await;
                                    let hostname: &str = config.hostname().into();
                                    let saved_hostname: &str = PROGRAM_CONFIG.hostname().into();
                                    writer
                                        .write_fmt(format_args!(
                                            "{} Hostname: \"{}\" [\"{}\"]\r\n",
                                            if hostname == saved_hostname { '-' } else { '*' },
                                            hostname,
                                            saved_hostname,
                                        ))
                                        .await;
                                    writer.write_fmt(format_args!("- Ports:\r\n")).await;
                                    for (i, (port, saved)) in
                                        config.ports.iter().zip(&PROGRAM_CONFIG.ports).enumerate()
                                    {
                                        writer
                                            .write_fmt(format_args!(
                                                "  {} {}: {} [{}]\r\n",
                                                if port == saved { '-' } else { '*' },
                                                i,
                                                port,
                                                saved,
                                            ))
                                            .await;
                                    }
                                }
                                Command::Save => write_program_config(flash, &config).unwrap(),
                                Command::Load(setting) => match setting {
                                    Setting::Vid => config.vid = PROGRAM_CONFIG.vid,
                                    Setting::Pid => config.pid = PROGRAM_CONFIG.pid,
                                    Setting::Manufacturer => {
                                        config.set_manufacturer(PROGRAM_CONFIG.manufacturer());
                                    }
                                    Setting::Product => {
                                        config.set_product(PROGRAM_CONFIG.product());
                                    }
                                    Setting::SerialNumber => {
                                        config.set_serial_number(PROGRAM_CONFIG.serial_number());
                                    }
                                    Setting::Mac => config.mac = PROGRAM_CONFIG.mac,
                                    Setting::Ip => config.ip = PROGRAM_CONFIG.ip,
                                    Setting::SubnetMask => {
                                        config.subnet_mask = PROGRAM_CONFIG.subnet_mask;
                                    }
                                    Setting::Gateway => {
                                        config.gateway_ip = PROGRAM_CONFIG.gateway_ip;
                                    }
                                    Setting::Hostname => {
                                        config.set_hostname(PROGRAM_CONFIG.hostname());
                                    }
                                    Setting::Port(socket) => {
                                        config.ports[socket as usize] =
                                            PROGRAM_CONFIG.ports[socket as usize];
                                    }
                                    Setting::All => config = PROGRAM_CONFIG.clone(),
                                },
                                Command::Set(setting) => match setting {
                                    SettingValue::Vid(vid) => config.vid = vid,
                                    SettingValue::Pid(pid) => config.pid = pid,
                                    SettingValue::Manufacturer(manufacturer) => {
                                        config.set_manufacturer(manufacturer);
                                    }
                                    SettingValue::Product(product) => config.set_product(product),
                                    SettingValue::SerialNumber(serial) => {
                                        config.set_serial_number(serial);
                                    }
                                    SettingValue::Mac(mac) => config.mac = mac,
                                    SettingValue::Ip(ip) => config.ip = ip,
                                    SettingValue::SubnetMask(subnet) => config.subnet_mask = subnet,
                                    SettingValue::Gateway(gateway) => config.gateway_ip = gateway,
                                    SettingValue::Hostname(hostname) => {
                                        config.set_hostname(hostname);
                                    }
                                    SettingValue::Port { socket, addr } => {
                                        config.ports[socket as usize] = addr;
                                    }
                                },
                                Command::Unknown(s) => {
                                    if !s.is_empty() {
                                        writer
                                            .write_fmt(format_args!(
                                                "Unknown command: \"{}\"\r\n",
                                                s.escape_ascii()
                                            ))
                                            .await;
                                    }
                                }
                            }

                            writer.write_fmt(format_args!("> ")).await;

                            writer.finalize().await;

                            buf_len - rest.len()
                        } else {
                            trace!(
                                "{}",
                                defmt::Display2Format(&(buf[..buf_len].escape_ascii()))
                            );

                            // TODO: If the buffer is still full we need to clear it.

                            break;
                        };

                        buf.copy_within(used..buf_len, 0);
                        buf_len -= used;
                    }
                }
                Err(EndpointError::Disabled) => {}
                Err(EndpointError::BufferOverflow) => panic!("Buffer overflow"),
            }
        }
    }

    join(usb.run(), control_loop(&mut cdc_acm, &mut flash)).await;
}

const HELP_TEXT: &'static str = "\
help\r
  - prints this help text commands\r
list\r
  - print all settings with current values and saved values, marking modified\r
    settings\r
save\r
  - saves changed settings in flash memory\r
load <setting> | all\r
  - reset a setting to the saved value\r
  - \"all\" resets all settings\r
set <setting> <value>\r
  - sets setting with value, assuming it passes checks\r
";

#[derive(Debug, defmt::Format)]
enum Command<'a> {
    Help,
    List,
    Save,
    Load(Setting),
    Set(SettingValue<'a>),
    Unknown(&'a [u8]),
}

impl<'a> Command<'a> {
    fn parse(i: &'a [u8]) -> IResult<&'a [u8], Self> {
        terminated(
            alt((
                tag_no_case(b"help").map(|_| Command::Help),
                tag_no_case(b"list").map(|_| Command::List),
                tag_no_case(b"save").map(|_| Command::Save),
                tuple((tag_no_case(b"load"), space1, Setting::parse))
                    .map(|(_, _, s)| Self::Load(s)),
                tuple((tag_no_case(b"set"), space1, SettingValue::parse))
                    .map(|(_, _, s)| Self::Set(s)),
                take_till(|b| b == b'\n' || b == b'\r').map(Command::Unknown),
            )),
            tuple((space0, alt((tag(b"\r\n"), tag(b"\r"), tag(b"\n"))))),
        )(i)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, defmt::Format)]
enum Setting {
    // USB Settings
    Vid,
    Pid,
    Manufacturer,
    Product,
    SerialNumber,
    // Ethernet settings
    Mac,
    Ip,
    SubnetMask,
    Gateway,
    Hostname,
    Port(u8),
    // Other
    All,
}

impl Setting {
    fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        alt((
            tag_no_case(b"vid").map(|_| Self::Vid),
            tag_no_case(b"pid").map(|_| Self::Pid),
            tag_no_case(b"manufacturer").map(|_| Self::Manufacturer),
            tag_no_case(b"product").map(|_| Self::Product),
            tag_no_case(b"serial_number").map(|_| Self::SerialNumber),
            tag_no_case(b"mac").map(|_| Self::Mac),
            tag_no_case(b"ip").map(|_| Self::Ip),
            tag_no_case(b"subnet_mask").map(|_| Self::SubnetMask),
            tag_no_case(b"gateway").map(|_| Self::Gateway),
            tag_no_case(b"hostname").map(|_| Self::Hostname),
            tuple((tag_no_case(b"port"), space1, streaming::u8)).map(|(_, _, s)| Self::Port(s)),
            tag_no_case(b"all").map(|_| Self::All),
        ))(i)
    }
}

#[derive(Debug, defmt::Format)]
enum SettingValue<'a> {
    // USB Settings
    Vid(u16),
    Pid(u16),
    Manufacturer(Option<&'a str>),
    Product(Option<&'a str>),
    SerialNumber(Option<&'a str>),
    // Ethernet settings
    Mac(Eui48Addr),
    Ip(Ipv4Addr),
    SubnetMask(Ipv4Addr),
    Gateway(Ipv4Addr),
    Hostname(Hostname<'a>),
    Port { socket: u8, addr: SocketAddrV4 },
}

impl<'a> SettingValue<'a> {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (i, setting) = verify(Setting::parse, |s| s != &Setting::All)(input)?;
        match setting {
            Setting::Vid => preceded(space1, streaming::u16)
                .map(|vid| Self::Vid(vid))
                .parse(i),
            Setting::Pid => preceded(space1, streaming::u16)
                .map(|pid| Self::Pid(pid))
                .parse(i),
            Setting::Manufacturer => preceded(space1, parse_usb_desc_str)
                .map(Self::Manufacturer)
                .parse(i),
            Setting::Product => preceded(space1, parse_usb_desc_str)
                .map(Self::Product)
                .parse(i),
            Setting::SerialNumber => preceded(space1, parse_usb_desc_str)
                .map(Self::SerialNumber)
                .parse(i),
            Setting::Mac => preceded(space1, parse_eui48_addr).map(Self::Mac).parse(i),
            Setting::Ip => preceded(space1, parse_ipv4_addr).map(Self::Ip).parse(i),
            Setting::SubnetMask => preceded(space1, parse_ipv4_addr)
                .map(Self::SubnetMask)
                .parse(i),
            Setting::Gateway => preceded(space1, parse_ipv4_addr)
                .map(Self::Gateway)
                .parse(i),
            Setting::Hostname => preceded(space1, parse_hostname)
                .map(Self::Hostname)
                .parse(i),
            Setting::Port(socket) => tuple((space1, parse_ipv4_addr, space1, streaming::u16))
                .map(|(_, addr, _, port)| Self::Port {
                    socket,
                    addr: SocketAddrV4::new(addr, port),
                })
                .parse(i),
            Setting::All => unreachable!(),
        }
    }
}

fn parse_usb_desc_str<'a>(i: &'a [u8]) -> IResult<&'a [u8], Option<&'a str>> {
    verify(
        take_till(|b| b == b'\n' || b == b'\r').map(|s: &[u8]| {
            if s.is_empty() {
                None
            } else {
                core::str::from_utf8(s).ok()
            }
        }),
        |s| {
            s.map_or(true, |s| {
                s.len() < CONFIG_STR_SIZE && s.encode_utf16().count() * 2 + 2 <= CONFIG_DESC_SIZE
            })
        },
    )(i)
}

fn parse_ipv4_addr<'a>(i: &'a [u8]) -> IResult<&'a [u8], Ipv4Addr> {
    tuple((streaming::u8, streaming::u8, streaming::u8, streaming::u8))
        .map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
        .parse(i)
}

fn parse_eui48_addr<'a>(i: &'a [u8]) -> IResult<&'a [u8], Eui48Addr> {
    tuple((
        streaming::u8,
        streaming::u8,
        streaming::u8,
        streaming::u8,
        streaming::u8,
        streaming::u8,
    ))
    .map(|(a, b, c, d, e, f)| Eui48Addr::new(a, b, c, d, e, f))
    .parse(i)
}

// It is not empty.
// It is 253 or fewer characters.
// It does not start or end with '-' or '.'.
// It does not contain any characters outside of the alphanumeric range, except for '-' and '.'.
// Its labels (characters separated by .) are not empty.
// Its labels are 63 or fewer characters.
// Its labels do not start or end with '-' or '.'.
fn parse_hostname<'a>(i: &'a [u8]) -> IResult<&'a [u8], Hostname<'a>> {
    verify(
        take_while(|b| is_alphanumeric(b) || b == b'.' || b == b'-'),
        |s: &[u8]| {
            (1..=HOSTNAME_SIZE).contains(&s.len())
                && s[0] != b'-'
                && s[0] != b'.'
                && s.split(|b| b == &b'.').all(|l| {
                    (1..=HOSTNAME_LABEL_SIZE).contains(&l.len()) && l[0] != b'-' && l[0] != b'.'
                })
        },
    )
    .map(|s| Hostname::new_unwrapped(core::str::from_utf8(s).unwrap()))
    .parse(i)
}
