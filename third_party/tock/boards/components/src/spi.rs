//! Components for SPI.
//!
//! This provides three components.
//!
//! 1. `SpiMuxComponent` provides a virtualization layer for a SPI controller.
//!
//! 2. `SpiSyscallComponent` provides a controller system call interface to SPI.
//!
//! 3. `SpiPSyscallComponent` provides a peripheral system call interface to SPI.
//!
//! 4. `SpiComponent` provides a virtualized client to the SPI bus.
//!
//! `SpiSyscallComponent` is used for processes, while `SpiComponent` is used
//! for kernel capsules that need access to the SPI bus.
//!
//! Usage
//! -----
//! ```rust
//! let mux_spi = components::spi::SpiMuxComponent::new(&sam4l::spi::SPI).finalize(
//!     components::spi_mux_component_helper!(sam4l::spi::SpiHw));
//! let spi_syscalls = SpiSyscallComponent::new(mux_spi, 3).finalize(
//!     components::spi_syscalls_component_helper!(sam4l::spi::SpiHw));
//! let rf233_spi = SpiComponent::new(mux_spi, 3).finalize(
//!     components::spi_component_helper!(sam4l::spi::SpiHw));
//! ```

// Author: Philip Levis <pal@cs.stanford.edu>
// Last modified: 6/20/2018

use core::mem::MaybeUninit;

use capsules::spi_controller::{Spi, DEFAULT_READ_BUF_LENGTH, DEFAULT_WRITE_BUF_LENGTH};
use capsules::spi_peripheral::SpiPeripheral;
use capsules::virtual_spi::{MuxSpiMaster, SpiSlaveDevice, VirtualSpiMasterDevice};
use kernel::component::Component;
use kernel::hil::spi;
use kernel::{static_init, static_init_half};

// Setup static space for the objects.
#[macro_export]
macro_rules! spi_mux_component_helper {
    ($S:ty $(,)?) => {{
        use capsules::virtual_spi::MuxSpiMaster;
        use core::mem::MaybeUninit;
        static mut BUF: MaybeUninit<MuxSpiMaster<'static, $S>> = MaybeUninit::uninit();
        &mut BUF
    };};
}

#[macro_export]
macro_rules! spi_syscall_component_helper {
    ($S:ty $(,)?) => {{
        use capsules::spi_controller::Spi;
        use capsules::virtual_spi::VirtualSpiMasterDevice;
        use core::mem::MaybeUninit;
        static mut BUF1: MaybeUninit<VirtualSpiMasterDevice<'static, $S>> = MaybeUninit::uninit();
        static mut BUF2: MaybeUninit<Spi<'static, VirtualSpiMasterDevice<'static, $S>>> =
            MaybeUninit::uninit();
        (&mut BUF1, &mut BUF2)
    };};
}

#[macro_export]
macro_rules! spi_syscallp_component_helper {
    ($S:ty $(,)?) => {{
        use capsules::spi_peripheral::SpiPeripheral;
        use capsules::virtual_spi::SpiSlaveDevice;
        use core::mem::MaybeUninit;
        static mut BUF1: MaybeUninit<SpiSlaveDevice<'static, $S>> = MaybeUninit::uninit();
        static mut BUF2: MaybeUninit<SpiPeripheral<'static, SpiSlaveDevice<'static, $S>>> =
            MaybeUninit::uninit();
        (&mut BUF1, &mut BUF2)
    };};
}

#[macro_export]
macro_rules! spi_component_helper {
    ($S:ty $(,)?) => {{
        use capsules::virtual_spi::VirtualSpiMasterDevice;
        use core::mem::MaybeUninit;
        static mut BUF: MaybeUninit<VirtualSpiMasterDevice<'static, $S>> = MaybeUninit::uninit();
        &mut BUF
    };};
}

#[macro_export]
macro_rules! spi_peripheral_component_helper {
    ($S:ty $(,)?) => {{
        use capsules::spi_peripheral::SpiPeripheral;
        use core::mem::MaybeUninit;
        static mut BUF: MaybeUninit<SpiPeripheral<'static, $S>> = MaybeUninit::uninit();
        &mut BUF
    };};
}

pub struct SpiMuxComponent<S: 'static + spi::SpiMaster> {
    spi: &'static S,
}

pub struct SpiSyscallComponent<S: 'static + spi::SpiMaster> {
    spi_mux: &'static MuxSpiMaster<'static, S>,
    chip_select: S::ChipSelect,
}

pub struct SpiSyscallPComponent<S: 'static + spi::SpiSlave> {
    spi_slave: &'static S,
}

pub struct SpiComponent<S: 'static + spi::SpiMaster> {
    spi_mux: &'static MuxSpiMaster<'static, S>,
    chip_select: S::ChipSelect,
}

impl<S: 'static + spi::SpiMaster> SpiMuxComponent<S> {
    pub fn new(spi: &'static S) -> Self {
        SpiMuxComponent { spi: spi }
    }
}

impl<S: 'static + spi::SpiMaster> Component for SpiMuxComponent<S> {
    type StaticInput = &'static mut MaybeUninit<MuxSpiMaster<'static, S>>;
    type Output = &'static MuxSpiMaster<'static, S>;

    unsafe fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let mux_spi = static_init_half!(
            static_buffer,
            MuxSpiMaster<'static, S>,
            MuxSpiMaster::new(self.spi)
        );

        self.spi.set_client(mux_spi);
        self.spi.init();

        mux_spi
    }
}

impl<S: 'static + spi::SpiMaster> SpiSyscallComponent<S> {
    pub fn new(mux: &'static MuxSpiMaster<'static, S>, chip_select: S::ChipSelect) -> Self {
        SpiSyscallComponent {
            spi_mux: mux,
            chip_select: chip_select,
        }
    }
}

impl<S: 'static + spi::SpiMaster> Component for SpiSyscallComponent<S> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualSpiMasterDevice<'static, S>>,
        &'static mut MaybeUninit<Spi<'static, VirtualSpiMasterDevice<'static, S>>>,
    );
    type Output = &'static Spi<'static, VirtualSpiMasterDevice<'static, S>>;

    unsafe fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let syscall_spi_device = static_init_half!(
            static_buffer.0,
            VirtualSpiMasterDevice<'static, S>,
            VirtualSpiMasterDevice::new(self.spi_mux, self.chip_select)
        );

        let spi_syscalls = static_init_half!(
            static_buffer.1,
            Spi<'static, VirtualSpiMasterDevice<'static, S>>,
            Spi::new(syscall_spi_device)
        );

        let spi_read_buf =
            static_init!([u8; DEFAULT_READ_BUF_LENGTH], [0; DEFAULT_READ_BUF_LENGTH]);

        let spi_write_buf = static_init!(
            [u8; DEFAULT_WRITE_BUF_LENGTH],
            [0; DEFAULT_WRITE_BUF_LENGTH]
        );

        spi_syscalls.config_buffers(spi_read_buf, spi_write_buf);
        syscall_spi_device.set_client(spi_syscalls);

        spi_syscalls
    }
}

impl<S: 'static + spi::SpiSlave> SpiSyscallPComponent<S> {
    pub fn new(slave: &'static S) -> Self {
        SpiSyscallPComponent { spi_slave: slave }
    }
}

impl<S: 'static + spi::SpiSlave> Component for SpiSyscallPComponent<S> {
    type StaticInput = (
        &'static mut MaybeUninit<SpiSlaveDevice<'static, S>>,
        &'static mut MaybeUninit<SpiPeripheral<'static, SpiSlaveDevice<'static, S>>>,
    );
    type Output = &'static SpiPeripheral<'static, SpiSlaveDevice<'static, S>>;

    unsafe fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let syscallp_spi_device = static_init_half!(
            static_buffer.0,
            SpiSlaveDevice<'static, S>,
            SpiSlaveDevice::new(self.spi_slave)
        );

        let spi_syscallsp = static_init_half!(
            static_buffer.1,
            SpiPeripheral<'static, SpiSlaveDevice<'static, S>>,
            SpiPeripheral::new(syscallp_spi_device)
        );

        let spi_read_buf =
            static_init!([u8; DEFAULT_READ_BUF_LENGTH], [0; DEFAULT_READ_BUF_LENGTH]);

        let spi_write_buf = static_init!(
            [u8; DEFAULT_WRITE_BUF_LENGTH],
            [0; DEFAULT_WRITE_BUF_LENGTH]
        );

        spi_syscallsp.config_buffers(spi_read_buf, spi_write_buf);
        syscallp_spi_device.set_client(spi_syscallsp);

        spi_syscallsp
    }
}

impl<S: 'static + spi::SpiMaster> SpiComponent<S> {
    pub fn new(mux: &'static MuxSpiMaster<'static, S>, chip_select: S::ChipSelect) -> Self {
        SpiComponent {
            spi_mux: mux,
            chip_select: chip_select,
        }
    }
}

impl<S: 'static + spi::SpiMaster> Component for SpiComponent<S> {
    type StaticInput = &'static mut MaybeUninit<VirtualSpiMasterDevice<'static, S>>;
    type Output = &'static VirtualSpiMasterDevice<'static, S>;

    unsafe fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let spi_device = static_init_half!(
            static_buffer,
            VirtualSpiMasterDevice<'static, S>,
            VirtualSpiMasterDevice::new(self.spi_mux, self.chip_select)
        );

        spi_device
    }
}

pub struct SpiPeripheralComponent<S: 'static + spi::SpiSlave> {
    device: &'static S,
}

impl<S: 'static + spi::SpiSlave> SpiPeripheralComponent<S> {
    pub fn new(device: &'static S) -> Self {
        SpiPeripheralComponent { device }
    }
}

impl<S: 'static + spi::SpiSlave + kernel::hil::spi::SpiSlaveDevice> Component
    for SpiPeripheralComponent<S>
{
    type StaticInput = &'static mut MaybeUninit<SpiPeripheral<'static, S>>;
    type Output = &'static SpiPeripheral<'static, S>;

    unsafe fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let spi_device = static_init_half!(
            static_buffer,
            SpiPeripheral<'static, S>,
            SpiPeripheral::new(self.device)
        );

        spi_device
    }
}
