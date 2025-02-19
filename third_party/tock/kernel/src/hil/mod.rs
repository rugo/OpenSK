//! Public traits for interfaces between Tock components.

pub mod adc;
pub mod analog_comparator;
pub mod ble_advertising;
pub mod bus8080;
pub mod crc;
pub mod dac;
pub mod digest;
pub mod eic;
pub mod entropy;
pub mod firmware_protection;
pub mod flash;
pub mod gpio;
pub mod gpio_async;
pub mod i2c;
pub mod kv_system;
pub mod led;
pub mod log;
pub mod nonvolatile_storage;
pub mod pwm;
pub mod radio;
pub mod rng;
pub mod screen;
pub mod sensors;
pub mod spi;
pub mod symmetric_encryption;
pub mod text_screen;
pub mod time;
pub mod touch;
pub mod uart;
pub mod usb;
pub mod usb_hid;

/// Shared interface for configuring components.
pub trait Controller {
    type Config;

    fn configure(&self, _: Self::Config);
}
