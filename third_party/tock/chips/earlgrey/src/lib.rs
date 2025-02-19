//! Drivers and chip support for EarlGrey.

#![feature(asm, const_fn, naked_functions)]
#![no_std]
#![crate_name = "earlgrey"]
#![crate_type = "rlib"]

pub mod chip_config;
mod interrupts;

pub mod aes;
pub mod chip;
pub mod flash_ctrl;
pub mod gpio;
pub mod hmac;
pub mod i2c;
pub mod plic;
pub mod pwrmgr;
pub mod timer;
pub mod uart;
pub mod usbdev;
