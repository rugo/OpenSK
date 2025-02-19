//! ns16550 compatible UART driver.

pub const UART_BASE: StaticRef<UartRegisters> =
    unsafe { StaticRef::new(0x8000_2000 as *const UartRegisters) };

use core::cell::Cell;
use kernel::common::cells::OptionalCell;
use kernel::common::cells::TakeCell;
use kernel::common::registers::{register_bitfields, register_structs, ReadWrite};
use kernel::common::StaticRef;
use kernel::hil;
use kernel::ReturnCode;

register_structs! {
    pub UartRegisters {
        (0x00 => brdl: ReadWrite<u32>),
        (0x04 => ier: ReadWrite<u32>),
        (0x08 => fcr: ReadWrite<u32, FCR::Register>),
        (0x0C => lcr: ReadWrite<u32>),
        (0x10 => _reserved0),
        (0x14 => lsr: ReadWrite<u32>),
        (0x18 => @END),
    }
}

register_bitfields![u32,
    FCR [
        CLEAR_RX OFFSET(1) NUMBITS(1) [],
        CLEAR_TX OFFSET(2) NUMBITS(1) [],
        FIFO_TRIG_LVL OFFSET(6) NUMBITS(2) [
            ONE_BYTE = 0,
            FOUR_BYTE = 1,
            EIGHT_BYTE = 2,
            FOURTEEN_BYTE = 3,
        ],
    ],
];

pub struct Uart<'a> {
    registers: StaticRef<UartRegisters>,
    tx_client: OptionalCell<&'a dyn hil::uart::TransmitClient>,
    rx_client: OptionalCell<&'a dyn hil::uart::ReceiveClient>,
    buffer: TakeCell<'static, [u8]>,
    len: Cell<usize>,
    index: Cell<usize>,
}

impl<'a> Uart<'a> {
    pub const fn new(base: StaticRef<UartRegisters>) -> Uart<'a> {
        Uart {
            registers: base,
            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),
            buffer: TakeCell::empty(),
            len: Cell::new(0),
            index: Cell::new(0),
        }
    }

    pub fn handle_interrupt(&self) {
        // Disable the interrupt
        self.registers.fcr.modify(FCR::CLEAR_TX::SET);

        if self.len.get() == self.index.get() {
            // We are done.
            self.index.set(0);

            // Signal client write done
            self.tx_client.map(|client| {
                self.buffer.take().map(|buffer| {
                    client.transmitted_buffer(buffer, self.len.get(), ReturnCode::SUCCESS);
                });
            });
        } else {
            self.buffer.map(|tx_data| {
                // Fill the TX buffer until it reports full.
                for i in self.index.get()..self.len.get() {
                    // Chek to see if the buffer is full
                    if self.registers.lsr.get() & 0x20 == 0 {
                        break;
                    }

                    // Write the byte from the array to the tx register.
                    self.registers.brdl.set(tx_data[i] as u32);
                    self.index.set(i + 1);
                }
            });
        }
    }

    fn enable_interrupts(&self) {
        self.registers.ier.set(0xF);
    }
}

impl<'a> hil::uart::UartData<'a> for Uart<'a> {}
impl<'a> hil::uart::Uart<'a> for Uart<'a> {}

impl hil::uart::Configure for Uart<'_> {
    fn configure(&self, params: hil::uart::Parameters) -> ReturnCode {
        // This chip does not support these features.
        if params.parity != hil::uart::Parity::None {
            return ReturnCode::ENOSUPPORT;
        }
        if params.hw_flow_control != false {
            return ReturnCode::ENOSUPPORT;
        }

        // Set DLAB in LCR
        self.registers.lcr.set(0x80);

        // Set divisor reg
        self.registers.brdl.set(27);

        // 8 data bits, 1 stop bit, no parity, clear DLAB
        self.registers.lcr.set(0x3 | 0x00 | 0x00);

        self.registers
            .fcr
            .write(FCR::FIFO_TRIG_LVL::EIGHT_BYTE + FCR::CLEAR_TX::SET + FCR::CLEAR_RX::SET);

        self.enable_interrupts();

        ReturnCode::SUCCESS
    }
}

impl<'a> hil::uart::Transmit<'a> for Uart<'a> {
    fn set_transmit_client(&self, client: &'a dyn hil::uart::TransmitClient) {
        self.tx_client.set(client);
    }

    fn transmit_buffer(
        &self,
        tx_data: &'static mut [u8],
        tx_len: usize,
    ) -> (ReturnCode, Option<&'static mut [u8]>) {
        if tx_len == 0 {
            return (ReturnCode::ESIZE, Some(tx_data));
        }

        // Fill the TX buffer until it reports full.
        for i in 0..tx_len {
            // Chek to see if the buffer is full
            if self.registers.lsr.get() & 0x20 == 0 {
                break;
            }

            // Write the byte from the array to the tx register.
            self.registers.brdl.set(tx_data[i] as u32);
            self.index.set(i + 1);
        }

        // Save the buffer so we can keep sending it.
        self.buffer.replace(tx_data);
        self.len.set(tx_len);

        (ReturnCode::SUCCESS, None)
    }

    fn transmit_abort(&self) -> ReturnCode {
        ReturnCode::FAIL
    }

    fn transmit_word(&self, _word: u32) -> ReturnCode {
        ReturnCode::FAIL
    }
}

impl<'a> hil::uart::Receive<'a> for Uart<'a> {
    fn set_receive_client(&self, client: &'a dyn hil::uart::ReceiveClient) {
        self.rx_client.set(client);
    }

    fn receive_buffer(
        &self,
        _rx_buffer: &'static mut [u8],
        _rx_len: usize,
    ) -> (ReturnCode, Option<&'static mut [u8]>) {
        (ReturnCode::FAIL, None)
    }

    fn receive_abort(&self) -> ReturnCode {
        ReturnCode::FAIL
    }

    fn receive_word(&self) -> ReturnCode {
        ReturnCode::FAIL
    }
}
