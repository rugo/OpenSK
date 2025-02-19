//! Board file for Nucleo-F446RE development board
//!
//! - <https://www.st.com/en/evaluation-tools/nucleo-f446re.html>

#![no_std]
// Disable this attribute when documenting, as a workaround for
// https://github.com/rust-lang/rust/issues/62184.
#![cfg_attr(not(doc), no_main)]
#![deny(missing_docs)]

use capsules::virtual_alarm::VirtualMuxAlarm;
use kernel::capabilities;
use kernel::common::dynamic_deferred_call::{DynamicDeferredCall, DynamicDeferredCallClientState};
use kernel::component::Component;
use kernel::hil::gpio::Configure;
use kernel::hil::led::LedHigh;
use kernel::Platform;
use kernel::{create_capability, debug, static_init};
use stm32f446re::interrupt_service::Stm32f446reDefaultPeripherals;

/// Support routines for debugging I/O.
pub mod io;

// Unit Tests for drivers.
#[allow(dead_code)]
mod multi_alarm_test;
#[allow(dead_code)]
mod virtual_uart_rx_test;

// Number of concurrent processes this platform supports.
const NUM_PROCS: usize = 4;

// Actual memory for holding the active process structures.
static mut PROCESSES: [Option<&'static dyn kernel::procs::ProcessType>; NUM_PROCS] =
    [None, None, None, None];

// Static reference to chip for panic dumps.
static mut CHIP: Option<&'static stm32f446re::chip::Stm32f4xx<Stm32f446reDefaultPeripherals>> =
    None;

// How should the kernel respond when a process faults.
const FAULT_RESPONSE: kernel::procs::FaultResponse = kernel::procs::FaultResponse::Panic;

/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x2000] = [0; 0x2000];

/// A structure representing this platform that holds references to all
/// capsules for this platform.
struct NucleoF446RE {
    console: &'static capsules::console::Console<'static>,
    ipc: kernel::ipc::IPC<NUM_PROCS>,
    led: &'static capsules::led::LedDriver<
        'static,
        LedHigh<'static, stm32f446re::gpio::Pin<'static>>,
    >,
    button: &'static capsules::button::Button<'static, stm32f446re::gpio::Pin<'static>>,
    alarm: &'static capsules::alarm::AlarmDriver<
        'static,
        VirtualMuxAlarm<'static, stm32f446re::tim2::Tim2<'static>>,
    >,
}

/// Mapping of integer syscalls to objects that implement syscalls.
impl Platform for NucleoF446RE {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::Driver>) -> R,
    {
        match driver_num {
            capsules::console::DRIVER_NUM => f(Some(self.console)),
            capsules::led::DRIVER_NUM => f(Some(self.led)),
            capsules::button::DRIVER_NUM => f(Some(self.button)),
            capsules::alarm::DRIVER_NUM => f(Some(self.alarm)),
            kernel::ipc::DRIVER_NUM => f(Some(&self.ipc)),
            _ => f(None),
        }
    }
}

/// Helper function called during bring-up that configures DMA.
unsafe fn setup_dma(
    dma: &stm32f446re::dma1::Dma1,
    dma_streams: &'static [stm32f446re::dma1::Stream; 8],
    usart2: &'static stm32f446re::usart::Usart,
) {
    use stm32f446re::dma1::Dma1Peripheral;
    use stm32f446re::usart;

    dma.enable_clock();

    let usart2_tx_stream = &dma_streams[Dma1Peripheral::USART2_TX.get_stream_idx()];
    let usart2_rx_stream = &dma_streams[Dma1Peripheral::USART2_RX.get_stream_idx()];

    usart2.set_dma(
        usart::TxDMA(usart2_tx_stream),
        usart::RxDMA(usart2_rx_stream),
    );

    usart2_tx_stream.set_client(usart2);
    usart2_rx_stream.set_client(usart2);

    usart2_tx_stream.setup(Dma1Peripheral::USART2_TX);
    usart2_rx_stream.setup(Dma1Peripheral::USART2_RX);

    cortexm4::nvic::Nvic::new(Dma1Peripheral::USART2_TX.get_stream_irqn()).enable();
    cortexm4::nvic::Nvic::new(Dma1Peripheral::USART2_RX.get_stream_irqn()).enable();
}

/// Helper function called during bring-up that configures multiplexed I/O.
unsafe fn set_pin_primary_functions(
    syscfg: &stm32f446re::syscfg::Syscfg,
    exti: &stm32f446re::exti::Exti,
    gpio_ports: &'static stm32f446re::gpio::GpioPorts<'static>,
) {
    use stm32f446re::exti::LineId;
    use stm32f446re::gpio::{AlternateFunction, Mode, PinId, PortId};

    syscfg.enable_clock();

    gpio_ports.get_port_from_port_id(PortId::A).enable_clock();

    // User LD2 is connected to PA05. Configure PA05 as `debug_gpio!(0, ...)`
    gpio_ports.get_pin(PinId::PA05).map(|pin| {
        pin.make_output();

        // Configure kernel debug gpios as early as possible
        kernel::debug::assign_gpios(Some(pin), None, None);
    });

    // pa2 and pa3 (USART2) is connected to ST-LINK virtual COM port
    gpio_ports.get_pin(PinId::PA02).map(|pin| {
        pin.set_mode(Mode::AlternateFunctionMode);
        // AF7 is USART2_TX
        pin.set_alternate_function(AlternateFunction::AF7);
    });
    gpio_ports.get_pin(PinId::PA03).map(|pin| {
        pin.set_mode(Mode::AlternateFunctionMode);
        // AF7 is USART2_RX
        pin.set_alternate_function(AlternateFunction::AF7);
    });

    gpio_ports.get_port_from_port_id(PortId::C).enable_clock();

    // button is connected on pc13
    gpio_ports.get_pin(PinId::PC13).map(|pin| {
        // By default, upon reset, the pin is in input mode, with no internal
        // pull-up, no internal pull-down (i.e., floating).
        //
        // Only set the mapping between EXTI line and the Pin and let capsule do
        // the rest.
        exti.associate_line_gpiopin(LineId::Exti13, pin);
    });
    // EXTI13 interrupts is delivered at IRQn 40 (EXTI15_10)
    cortexm4::nvic::Nvic::new(stm32f446re::nvic::EXTI15_10).enable();
}

/// Helper function for miscellaneous peripheral functions
unsafe fn setup_peripherals(tim2: &stm32f446re::tim2::Tim2) {
    // USART2 IRQn is 38
    cortexm4::nvic::Nvic::new(stm32f446re::nvic::USART2).enable();

    // TIM2 IRQn is 28
    tim2.enable_clock();
    tim2.start();
    cortexm4::nvic::Nvic::new(stm32f446re::nvic::TIM2).enable();
}

/// Reset Handler.
///
/// This symbol is loaded into vector table by the STM32F446RE chip crate.
/// When the chip first powers on or later does a hard reset, after the core
/// initializes all the hardware, the address of this function is loaded and
/// execution begins here.
#[no_mangle]
pub unsafe fn reset_handler() {
    stm32f446re::init();

    // We use the default HSI 16Mhz clock
    let rcc = static_init!(stm32f446re::rcc::Rcc, stm32f446re::rcc::Rcc::new());
    let syscfg = static_init!(
        stm32f446re::syscfg::Syscfg,
        stm32f446re::syscfg::Syscfg::new(rcc)
    );
    let exti = static_init!(
        stm32f446re::exti::Exti,
        stm32f446re::exti::Exti::new(syscfg)
    );
    let dma1 = static_init!(stm32f446re::dma1::Dma1, stm32f446re::dma1::Dma1::new(rcc));
    let peripherals = static_init!(
        Stm32f446reDefaultPeripherals,
        Stm32f446reDefaultPeripherals::new(rcc, exti, dma1)
    );
    peripherals.init();
    let base_peripherals = &peripherals.stm32f4;

    setup_peripherals(&base_peripherals.tim2);

    set_pin_primary_functions(syscfg, &base_peripherals.exti, &base_peripherals.gpio_ports);

    setup_dma(
        dma1,
        &base_peripherals.dma_streams,
        &base_peripherals.usart2,
    );

    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(&PROCESSES));
    let dynamic_deferred_call_clients =
        static_init!([DynamicDeferredCallClientState; 2], Default::default());
    let dynamic_deferred_caller = static_init!(
        DynamicDeferredCall,
        DynamicDeferredCall::new(dynamic_deferred_call_clients)
    );
    DynamicDeferredCall::set_global_instance(dynamic_deferred_caller);

    let chip = static_init!(
        stm32f446re::chip::Stm32f4xx<Stm32f446reDefaultPeripherals>,
        stm32f446re::chip::Stm32f4xx::new(peripherals)
    );
    CHIP = Some(chip);

    // UART

    // Create a shared UART channel for kernel debug.
    base_peripherals.usart2.enable_clock();
    let uart_mux = components::console::UartMuxComponent::new(
        &base_peripherals.usart2,
        115200,
        dynamic_deferred_caller,
    )
    .finalize(());

    // `finalize()` configures the underlying USART, so we need to
    // tell `send_byte()` not to configure the USART again.
    io::WRITER.set_initialized();

    // Create capabilities that the board needs to call certain protected kernel
    // functions.
    let memory_allocation_capability = create_capability!(capabilities::MemoryAllocationCapability);
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);
    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);

    // Setup the console.
    let console = components::console::ConsoleComponent::new(board_kernel, uart_mux).finalize(());
    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new(uart_mux).finalize(());

    // // Setup the process inspection console
    // let process_console_uart = static_init!(UartDevice, UartDevice::new(mux_uart, true));
    // process_console_uart.setup();
    // pub struct ProcessConsoleCapability;
    // unsafe impl capabilities::ProcessManagementCapability for ProcessConsoleCapability {}
    // let process_console = static_init!(
    //     capsules::process_console::ProcessConsole<'static, ProcessConsoleCapability>,
    //     capsules::process_console::ProcessConsole::new(
    //         process_console_uart,
    //         &mut capsules::process_console::WRITE_BUF,
    //         &mut capsules::process_console::READ_BUF,
    //         &mut capsules::process_console::COMMAND_BUF,
    //         board_kernel,
    //         ProcessConsoleCapability,
    //     )
    // );
    // hil::uart::Transmit::set_transmit_client(process_console_uart, process_console);
    // hil::uart::Receive::set_receive_client(process_console_uart, process_console);
    // process_console.start();

    // LEDs
    let gpio_ports = &base_peripherals.gpio_ports;

    // Clock to Port A is enabled in `set_pin_primary_functions()`
    let led = components::led::LedsComponent::new(components::led_component_helper!(
        LedHigh<'static, stm32f446re::gpio::Pin>,
        LedHigh::new(gpio_ports.get_pin(stm32f446re::gpio::PinId::PA05).unwrap()),
    ))
    .finalize(components::led_component_buf!(
        LedHigh<'static, stm32f446re::gpio::Pin>
    ));

    // BUTTONs
    let button = components::button::ButtonComponent::new(
        board_kernel,
        components::button_component_helper!(
            stm32f446re::gpio::Pin,
            (
                gpio_ports.get_pin(stm32f446re::gpio::PinId::PC13).unwrap(),
                kernel::hil::gpio::ActivationMode::ActiveLow,
                kernel::hil::gpio::FloatingState::PullNone
            )
        ),
    )
    .finalize(components::button_component_buf!(stm32f446re::gpio::Pin));

    // ALARM
    let tim2 = &base_peripherals.tim2;
    let mux_alarm = components::alarm::AlarmMuxComponent::new(tim2).finalize(
        components::alarm_mux_component_helper!(stm32f446re::tim2::Tim2),
    );

    let alarm = components::alarm::AlarmDriverComponent::new(board_kernel, mux_alarm)
        .finalize(components::alarm_component_helper!(stm32f446re::tim2::Tim2));

    let nucleo_f446re = NucleoF446RE {
        console: console,
        ipc: kernel::ipc::IPC::new(board_kernel, &memory_allocation_capability),
        led: led,
        button: button,
        alarm: alarm,
    };

    // // Optional kernel tests
    // //
    // // See comment in `boards/imix/src/main.rs`
    // virtual_uart_rx_test::run_virtual_uart_receive(mux_uart);

    debug!("Initialization complete. Entering main loop");

    /// These symbols are defined in the linker script.
    extern "C" {
        /// Beginning of the ROM region containing app images.
        static _sapps: u8;
        /// End of the ROM region containing app images.
        static _eapps: u8;
        /// Beginning of the RAM region for app memory.
        static mut _sappmem: u8;
        /// End of the RAM region for app memory.
        static _eappmem: u8;
    }

    kernel::procs::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            &_sapps as *const u8,
            &_eapps as *const u8 as usize - &_sapps as *const u8 as usize,
        ),
        core::slice::from_raw_parts_mut(
            &mut _sappmem as *mut u8,
            &_eappmem as *const u8 as usize - &_sappmem as *const u8 as usize,
        ),
        &mut PROCESSES,
        FAULT_RESPONSE,
        &process_management_capability,
    )
    .unwrap_or_else(|err| {
        debug!("Error loading processes!");
        debug!("{:?}", err);
    });

    let scheduler = components::sched::round_robin::RoundRobinComponent::new(&PROCESSES)
        .finalize(components::rr_component_helper!(NUM_PROCS));

    //Uncomment to run multi alarm test
    //multi_alarm_test::run_multi_alarm(mux_alarm);
    board_kernel.kernel_loop(
        &nucleo_f446re,
        chip,
        Some(&nucleo_f446re.ipc),
        scheduler,
        &main_loop_capability,
    );
}
