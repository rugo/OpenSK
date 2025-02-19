use core::cell::Cell;
use core::fmt::Write;
use core::panic::PanicInfo;
use core::str;
use kernel::debug;
use kernel::debug::IoWrite;
use rv32i;

use crate::{PANIC_REFERENCES, PROCESSES};

struct Writer {}

static mut WRITER: Writer = Writer {};

impl Write for Writer {
    fn write_str(&mut self, s: &str) -> ::core::fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

impl IoWrite for Writer {
    fn write(&mut self, buf: &[u8]) {
        unsafe {
            PANIC_REFERENCES.uart.unwrap().transmit_sync(buf);
        }
    }
}

// The LiteX simulation does not have LEDs, hence use a dummy type for
// the debug::panic function
struct DummyLed(Cell<bool>);
impl kernel::hil::led::Led for DummyLed {
    fn init(&self) {
        self.0.set(false);
    }
    fn on(&self) {
        self.0.set(true);
    }
    fn off(&self) {
        self.0.set(false);
    }
    fn toggle(&self) {
        self.0.set(!self.0.get());
    }
    fn read(&self) -> bool {
        self.0.get()
    }
}

/// Panic handler.
#[cfg(not(test))]
#[no_mangle]
#[panic_handler]
pub unsafe extern "C" fn panic_fmt(pi: &PanicInfo) -> ! {
    let writer = &mut WRITER;

    debug::panic::<DummyLed, _, _>(
        &mut [],
        writer,
        pi,
        &rv32i::support::nop,
        &PROCESSES,
        &PANIC_REFERENCES.chip,
    )
}
