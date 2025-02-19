//! Component for BLE radio on nRF52 based platforms.
//!
//! Usage
//! -----
//! ```rust
//! let ble_radio = BLEComponent::new(board_kernel, &nrf52::ble_radio::RADIO, mux_alarm).finalize();
//! ```

use capsules;
use capsules::virtual_alarm::VirtualMuxAlarm;

use nrf52::rtc::Rtc;

use kernel::capabilities;
use kernel::component::Component;
use kernel::hil::time::Alarm;
use kernel::{create_capability, static_init};

// Save some deep nesting

pub struct BLEComponent {
    board_kernel: &'static kernel::Kernel,
    radio: &'static nrf52::ble_radio::Radio<'static>,
    mux_alarm: &'static capsules::virtual_alarm::MuxAlarm<'static, nrf52::rtc::Rtc<'static>>,
}

impl BLEComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        radio: &'static nrf52::ble_radio::Radio,
        mux_alarm: &'static capsules::virtual_alarm::MuxAlarm<'static, nrf52::rtc::Rtc>,
    ) -> BLEComponent {
        BLEComponent {
            board_kernel: board_kernel,
            radio: radio,
            mux_alarm: mux_alarm,
        }
    }
}

impl Component for BLEComponent {
    type StaticInput = ();
    type Output = &'static capsules::ble_advertising_driver::BLE<
        'static,
        nrf52::ble_radio::Radio<'static>,
        VirtualMuxAlarm<'static, Rtc<'static>>,
    >;

    unsafe fn finalize(self, _s: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let ble_radio_virtual_alarm = static_init!(
            capsules::virtual_alarm::VirtualMuxAlarm<'static, nrf52::rtc::Rtc>,
            capsules::virtual_alarm::VirtualMuxAlarm::new(self.mux_alarm)
        );

        let ble_radio = static_init!(
            capsules::ble_advertising_driver::BLE<
                'static,
                nrf52::ble_radio::Radio,
                VirtualMuxAlarm<'static, Rtc>,
            >,
            capsules::ble_advertising_driver::BLE::new(
                self.radio,
                self.board_kernel.create_grant(&grant_cap),
                &mut capsules::ble_advertising_driver::BUF,
                ble_radio_virtual_alarm
            )
        );
        kernel::hil::ble_advertising::BleAdvertisementDriver::set_receive_client(
            self.radio, ble_radio,
        );
        kernel::hil::ble_advertising::BleAdvertisementDriver::set_transmit_client(
            self.radio, ble_radio,
        );
        ble_radio_virtual_alarm.set_alarm_client(ble_radio);

        ble_radio
    }
}
