//! Test that an Alarm implementation is working by trying a few edge
//! cases on the delay, including delays of 1 and 0 delays. Depends
//! on a working UART and debug! macro.
//!
//! Author: Philip Levis <plevis@google.com>
//! Last Modified: 6/17/2020
use core::cell::Cell;
use kernel::debug;
use kernel::hil::time::{Alarm, AlarmClient, Ticks};

pub struct TestRandomAlarm<'a, A: Alarm<'a>> {
    alarm: &'a A,
    counter: Cell<usize>,
    expected: Cell<A::Ticks>,
    _id: char,
}

impl<'a, A: Alarm<'a>> TestRandomAlarm<'a, A> {
    pub fn new(alarm: &'a A, value: usize, ch: char) -> TestRandomAlarm<'a, A> {
        TestRandomAlarm {
            alarm: alarm,
            counter: Cell::new(value),
            expected: Cell::new(A::ticks_from_seconds(0)),
            _id: ch,
        }
    }

    pub fn run(&self) {
        debug!("Starting random alarm test Test{}.", self._id);
        self.set_next_alarm();
    }

    fn set_next_alarm(&self) {
        let counter = self.counter.get();
        let mut us: u32 = 3 * ((counter * 668410) % 512507) as u32;
        if us % 11 == 0 {
            // Try delays of zero in 1 of 11 cases
            us = 0;
        }
        let delay = A::ticks_from_us(us);
        let now = self.alarm.now();
        // Subtract 0-9 so we are always asking from the past.
        // If the delay is already 0, don't subtract anything.
        let start = now.wrapping_sub(A::Ticks::from(us % 10));
        self.alarm.set_alarm(start, delay);
        debug!(
            "Test{}@{:?}: Expected at {:?} (diff = {:?}), setting alarm to {:?} (delay = {:?})",
            self._id,
            now,
            self.expected.get(),
            now.wrapping_sub(self.expected.get()),
            start.wrapping_add(delay),
            delay
        );
        self.counter.set(counter + 1);
        self.expected.set(start.wrapping_add(delay));
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for TestRandomAlarm<'a, A> {
    fn alarm(&self) {
        debug!("Test{}: Alarm fired.", self._id);
        self.set_next_alarm();
    }
}
