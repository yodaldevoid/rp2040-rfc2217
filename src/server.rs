use defmt::{info, todo};

use embassy_executor::Spawner;
use embassy_rp::{interrupt::USBCTRL_IRQ, Peripherals};

pub async fn run(_spawner: Spawner, _p: Peripherals, _irq: USBCTRL_IRQ) {
    info!("Server interface selected");

    todo!("server")
}
