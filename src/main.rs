#![no_std]
#![no_main]
#![feature(type_alias_impl_trait, async_fn_in_trait, async_closure)]
#![allow(incomplete_features)]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_rp::{
    gpio::{Input, Level, Pull},
    interrupt,
};
use panic_probe as _;

pub mod binary_info;
mod client;
pub(crate) mod control;
mod server;
mod telnet;
pub(crate) mod utils;

const PACKET_SIZE: usize = 64;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello there!");

    let mut p = embassy_rp::init(Default::default());

    let (usb_id, control_boot) = {
        let usb_id = Input::new(&mut p.PIN_1, Pull::Up);
        let control_boot = Input::new(&mut p.PIN_0, Pull::Up);
        (usb_id.get_level(), control_boot.get_level())
    };

    // This IRQ is setup in a central location so it doesn't try to create multiple
    // ISRs.
    let irq = interrupt::take!(USBCTRL_IRQ);

    if usb_id == Level::High {
        server::run(spawner, p, irq).await
    } else if control_boot == Level::Low {
        control::run(spawner, p, irq).await
    } else {
        client::run(spawner, p, irq).await
    }
}
