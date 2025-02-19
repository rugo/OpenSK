//! ARM Cortex-M SysTick peripheral.

use kernel::common::registers::{register_bitfields, FieldValue, ReadOnly, ReadWrite};
use kernel::common::StaticRef;

#[repr(C)]
struct SystickRegisters {
    syst_csr: ReadWrite<u32, ControlAndStatus::Register>,
    syst_rvr: ReadWrite<u32, ReloadValue::Register>,
    syst_cvr: ReadWrite<u32, CurrentValue::Register>,
    syst_calib: ReadOnly<u32, CalibrationValue::Register>,
}

register_bitfields![u32,
    ControlAndStatus [
        /// Returns 1 if timer counted to 0 since last time this was read.
        COUNTFLAG 16,

        /// Clock source is (0) External Clock or (1) Processor Clock.
        CLKSOURCE 2,

        /// Set to 1 to enable SysTick exception request.
        TICKINT 1,

        /// Enable the counter (1 == Enabled).
        ENABLE 0
    ],

    ReloadValue [
        /// Value loaded to `syst_csr` when counter is enabled and reaches 0.
        RELOAD          OFFSET(0)  NUMBITS(24)
    ],

    CurrentValue [
        /// Reads current value. Write of any value sets to 0.
        CURRENT         OFFSET(0)  NUMBITS(24)
    ],

    CalibrationValue [
        /// 0 if device provides reference clock to processor.
        NOREF           OFFSET(31) NUMBITS(1),

        /// 0 if TENMS value is exact, 1 if inexact or not given.
        SKEW            OFFSET(30) NUMBITS(1),

        /// Reload value for 10ms ticks, or 0 if no calibration.
        TENMS           OFFSET(0)  NUMBITS(24)
    ]
];

/// The ARM Cortex-M SysTick peripheral
///
/// Documented in the Cortex-MX Devices Generic User Guide, Chapter 4.4
pub struct SysTick {
    hertz: u32,
    external_clock: bool,
}

const BASE_ADDR: *const SystickRegisters = 0xE000E010 as *const SystickRegisters;
const SYSTICK_BASE: StaticRef<SystickRegisters> =
    unsafe { StaticRef::new(BASE_ADDR as *const SystickRegisters) };

impl SysTick {
    /// Initialize the `SysTick` with default values
    ///
    /// Use this constructor if the core implementation has a pre-calibration
    /// value in hardware.
    pub unsafe fn new() -> SysTick {
        SysTick {
            hertz: 0,
            external_clock: false,
        }
    }

    /// Initialize the `SysTick` with an explicit clock speed
    ///
    /// Use this constructor if the core implementation does not have a
    /// pre-calibration value.
    ///
    ///   * `clock_speed` - the frequency of SysTick tics in Hertz. For example,
    ///   if the SysTick is driven by the CPU clock, it is simply the CPU speed.
    pub unsafe fn new_with_calibration(clock_speed: u32) -> SysTick {
        let mut res = SysTick::new();
        res.hertz = clock_speed;
        res
    }

    /// Initialize the `SysTick` with an explicit clock speed and external source
    ///
    /// Use this constructor if the core implementation does not have a
    /// pre-calibration value and you need an external clock source for  
    /// the Systick.
    ///
    ///   * `clock_speed` - the frequency of SysTick tics in Hertz. For example,
    ///   if the SysTick is driven by the CPU clock, it is simply the CPU speed.
    pub unsafe fn new_with_calibration_and_external_clock(clock_speed: u32) -> SysTick {
        let mut res = SysTick::new();
        res.hertz = clock_speed;
        res.external_clock = true;
        res
    }

    // Return the tic frequency in hertz. If the value is configured by the
    // user using the `new_with_calibration` constructor return `self.hertz`.
    // Otherwise, compute the frequncy using the calibration value that is set
    // in hardware.
    fn hertz(&self) -> u32 {
        if self.hertz != 0 {
            self.hertz
        } else {
            // The `tenms` register is the reload value for 10ms, so
            // Hertz = number of tics in 1 second = tenms * 100
            let tenms = SYSTICK_BASE.syst_calib.read(CalibrationValue::TENMS);
            tenms * 100
        }
    }
}

impl kernel::SchedulerTimer for SysTick {
    fn start(&self, us: u32) {
        let reload = {
            // We need to convert from microseconds to native tics, which could overflow in 32-bit
            // arithmetic. So we convert to 64-bit. 64-bit division is an expensive subroutine, but
            // if `us` is a power of 10 the compiler will simplify it with the 1_000_000 divisor
            // instead.
            let us = us as u64;
            let hertz = self.hertz() as u64;

            hertz * us / 1_000_000
        };
        let clock_source: FieldValue<u32, self::ControlAndStatus::Register> = if self.external_clock
        {
            // CLKSOURCE 0 --> external clock
            ControlAndStatus::CLKSOURCE::CLEAR
        } else {
            // CLKSOURCE 1 --> internal clock
            ControlAndStatus::CLKSOURCE::SET
        };

        // n.b.: 4.4.5 'hints and tips' suggests setting reload before value
        SYSTICK_BASE
            .syst_rvr
            .write(ReloadValue::RELOAD.val(reload as u32));
        SYSTICK_BASE.syst_cvr.set(0);

        // OK, arm it
        // We really just need to set the TICKINT bit here, but can't use modify() because
        // readying the CSR register will throw away evidence of expiration if one
        // occurred, so we re-write entire value instead.
        SYSTICK_BASE
            .syst_csr
            .write(ControlAndStatus::TICKINT::SET + ControlAndStatus::ENABLE::SET + clock_source);
    }

    fn reset(&self) {
        SYSTICK_BASE.syst_csr.set(0);
        SYSTICK_BASE.syst_rvr.set(0);
        SYSTICK_BASE.syst_cvr.set(0);
    }

    fn arm(&self) {
        let clock_source: FieldValue<u32, self::ControlAndStatus::Register> = if self.external_clock
        {
            // CLKSOURCE 0 --> external clock
            ControlAndStatus::CLKSOURCE::CLEAR
        } else {
            // CLKSOURCE 1 --> internal clock
            ControlAndStatus::CLKSOURCE::SET
        };

        // We really just need to set the TICKINT bit here, but can't use modify() because
        // readying the CSR register will throw away evidence of expiration if one
        // occurred, so we re-write entire value instead.
        SYSTICK_BASE
            .syst_csr
            .write(ControlAndStatus::TICKINT::SET + ControlAndStatus::ENABLE::SET + clock_source);
    }

    fn disarm(&self) {
        let clock_source: FieldValue<u32, self::ControlAndStatus::Register> = if self.external_clock
        {
            // CLKSOURCE 0 --> external clock
            ControlAndStatus::CLKSOURCE::CLEAR
        } else {
            // CLKSOURCE 1 --> internal clock
            ControlAndStatus::CLKSOURCE::SET
        };

        // We really just need to set the TICKINT bit here, but can't use modify() because
        // readying the CSR register will throw away evidence of expiration if one
        // occurred, so we re-write entire value instead.
        SYSTICK_BASE
            .syst_csr
            .write(ControlAndStatus::TICKINT::CLEAR + ControlAndStatus::ENABLE::SET + clock_source);
    }

    fn get_remaining_us(&self) -> Option<u32> {
        // use u64 in case of overflow when multiplying by 1,000,000
        let tics = SYSTICK_BASE.syst_cvr.read(CurrentValue::CURRENT) as u64;
        if SYSTICK_BASE.syst_csr.is_set(ControlAndStatus::COUNTFLAG) {
            None
        } else {
            let hertz = self.hertz() as u64;
            Some(((tics * 1_000_000) / hertz) as u32)
        }
    }
}
