//! Shared implementations for ARM Cortex-M0 MCUs.

#![crate_name = "cortexm0"]
#![crate_type = "rlib"]
#![feature(asm, naked_functions)]
#![no_std]

// Re-export the base generic cortex-m functions here as they are
// valid on cortex-m0.
pub use cortexm::support;

pub use cortexm::nvic;
pub use cortexm::print_cortexm_state as print_cortexm0_state;
pub use cortexm::syscall;

extern "C" {
    // _estack is not really a function, but it makes the types work
    // You should never actually invoke it!!
    fn _estack();
    static mut _sstack: u32;
    static mut _szero: u32;
    static mut _ezero: u32;
    static mut _etext: u32;
    static mut _srelocate: u32;
    static mut _erelocate: u32;
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn generic_isr() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
/// All ISRs are caught by this handler which disables the NVIC and switches to the kernel.
pub unsafe extern "C" fn generic_isr() {
    asm!(
        "
    /* Skip saving process state if not coming from user-space */
    ldr r0, MEXC_RETURN_PSP
    cmp lr, r0
    bne _ggeneric_isr_no_stacking

    /* We need the most recent kernel's version of r1, which points */
    /* to the Process struct's stored registers field. The kernel's r1 */
    /* lives in the second word of the hardware stacked registers on MSP */
    mov r1, sp
    ldr r1, [r1, #4]
    str r4, [r1, #16]
    str r5, [r1, #20]
    str r6, [r1, #24]
    str r7, [r1, #28]

    push {r4-r7}
    mov  r4, r8
    mov  r5, r9
    mov  r6, r10
    mov  r7, r11
    str r4, [r1, #0]
    str r5, [r1, #4]
    str r6, [r1, #8]
    str r7, [r1, #12]
    pop {r4-r7}

    ldr r0, MEXC_RETURN_MSP
_ggeneric_isr_no_stacking:
    /* Find the ISR number by looking at the low byte of the IPSR registers */
    mrs r0, IPSR
    movs r1, #0xff
    ands r0, r1
    /* ISRs start at 16, so substract 16 to get zero-indexed */
    subs r0, r0, #16

    /*
     * High level:
     *    NVIC.ICER[r0 / 32] = 1 << (r0 & 31)
     * */
    /* r3 = &NVIC.ICER[r0 / 32] */
    ldr r2, NVICICER     /* r2 = &NVIC.ICER */
    lsrs r3, r0, #5   /* r3 = r0 / 32 */
    lsls r3, r3, #2   /* ICER is word-sized, so multiply offset by 4 */
    adds r3, r3, r2   /* r3 = r2 + r3 */

    /* r2 = 1 << (r0 & 31) */
    movs r2, #31      /* r2 = 31 */
    ands r0, r2       /* r0 = r0 & r2 */
    subs r2, r2, #30  /* r2 = r2 - 30 i.e. r2 = 1 */
    lsls r2, r2, r0   /* r2 = 1 << r0 */

    /* *r3 = r2 */
    str r2, [r3]

    /* The pending bit in ISPR might be reset by hardware for pulse interrupts
     * at this point. So set it here again so the interrupt does not get lost
     * in service_pending_interrupts()
     *
     * The NVIC.ISPR base is 0xE000E200, which is 0x20 (aka #32) above the
     * NVIC.ICER base.  Calculate the ISPR address by offsetting from the ICER
     * address so as to avoid re-doing the [r0 / 32] index math.
     */
    adds r3, #32
    str r2, [r3]

    bx lr /* return here since we have extra words in the assembly */

.align 4
NVICICER:
  .word 0xE000E180
MEXC_RETURN_MSP:
  .word 0xFFFFFFF9
MEXC_RETURN_PSP:
  .word 0xFFFFFFFD",
        options(noreturn)
    );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn svc_handler() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn svc_handler() {
    asm!(
        "
  ldr r0, EXC_RETURN_MSP
  cmp lr, r0
  bne to_kernel
  ldr r1, EXC_RETURN_PSP
  bx r1

to_kernel:
  ldr r0, =SYSCALL_FIRED
  movs r1, #1
  str r1, [r0, #0]
  ldr r1, EXC_RETURN_MSP
  bx r1

.align 4
EXC_RETURN_MSP:
  .word 0xFFFFFFF9
EXC_RETURN_PSP:
  .word 0xFFFFFFFD
  ",
        options(noreturn)
    );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn switch_to_user(
    _user_stack: *const u8,
    _process_regs: &mut [usize; 8],
) -> *mut u8 {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[no_mangle]
pub unsafe extern "C" fn switch_to_user(
    mut user_stack: *const u8,
    process_regs: &mut [usize; 8],
) -> *mut u8 {
    asm!("
    // Manually save r6 in r2 and r7 in r3 since as of Feb 2021 asm!() will not
    // let us mark r6 or r7 as clobbers.
    mov r2, r6
    mov r3, r7

    /* Load non-hardware-stacked registers from Process stack */
    ldmia r1!, {r4-r7}
    mov r11, r7
    mov r10, r6
    mov r9,  r5
    mov r8,  r4
    ldmia r1!, {r4-r7}
    subs r1, 32 /* Restore pointer to process_regs
                /* ldmia! added a 32-byte offset */

    /* Load bottom of stack into Process Stack Pointer */
    msr psp, r0

    /* SWITCH */
    svc 0xff /* It doesn't matter which SVC number we use here */

    /* Store non-hardware-stacked registers in process_regs */
    /* r1 still points to process_regs because we are clobbering all */
    /* non-hardware-stacked registers */
    str r4, [r1, #16]
    str r5, [r1, #20]
    str r6, [r1, #24]
    str r7, [r1, #28]

    mov  r4, r8
    mov  r5, r9
    mov  r6, r10
    mov  r7, r11

    str r4, [r1, #0]
    str r5, [r1, #4]
    str r6, [r1, #8]
    str r7, [r1, #12]

    mrs r0, PSP /* PSP into user_stack */

    // Manually restore r6 and r7.
    mov r6, r2
    mov r7, r3

    ",
    inout("r0") user_stack,
    in("r1") process_regs,
    out("r2") _, out("r3") _, out("r4") _, out("r5") _, out("r8") _, out("r9") _,
    out("r10") _, out("r11") _);

    user_stack as *mut u8
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
struct HardFaultStackedRegisters {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r12: u32,
    lr: u32,
    pc: u32,
    xpsr: u32,
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[inline(never)]
unsafe fn kernel_hardfault(faulting_stack: *mut u32) {
    let hardfault_stacked_registers = HardFaultStackedRegisters {
        r0: *faulting_stack.offset(0),
        r1: *faulting_stack.offset(1),
        r2: *faulting_stack.offset(2),
        r3: *faulting_stack.offset(3),
        r12: *faulting_stack.offset(4),
        lr: *faulting_stack.offset(5),
        pc: *faulting_stack.offset(6),
        xpsr: *faulting_stack.offset(7),
    };

    // NOTE: Unlike Cortex-M3, `panic!` does not seem to work
    //       here. `panic!` seems to be producing wrong `PanicInfo`
    //       value. Therefore as a workaround, capture the stacked
    //       registers and invoke a breakpoint.
    //
    asm!(
        "
         bkpt
1:
         b 1b
         "
    );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn hard_fault_handler() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
/// Continue the hardfault handler. This function is not `#[naked]`, meaning we
/// can mix `asm!()` and Rust. We separate this logic to not have to write the
/// entire fault handler entirely in assembly.
unsafe extern "C" fn hard_fault_handler_continued(faulting_stack: *mut u32, kernel_stack: u32) {
    if kernel_stack {
        kernel_hardfault(faulting_stack);
    } else {
        // hard fault occurred in an app, not the kernel. The app should be
        // marked as in an error state and handled by the kernel
        asm!(
            "
            ldr r0, =APP_HARD_FAULT
            movs r1, #1 /* Fault */
            str r1, [r0, #0]

            /*
            * NOTE:
            * -----
            *
            * Even though ARMv6-M SCB and Control registers
            * are different from ARMv7-M, they are still compatible
            * with each other. So, we can keep the same code as
            * ARMv7-M.
            *
            * ARMv6-M however has no _privileged_ mode.
            */

            /* Read the SCB registers. */
            ldr r0, =SCB_REGISTERS
            ldr r1, =0xE000ED14
            ldr r2, [r1, #0] /* CCR */
            str r2, [r0, #0]
            ldr r2, [r1, #20] /* CFSR */
            str r2, [r0, #4]
            ldr r2, [r1, #24] /* HFSR */
            str r2, [r0, #8]
            ldr r2, [r1, #32] /* MMFAR */
            str r2, [r0, #12]
            ldr r2, [r1, #36] /* BFAR */
            str r2, [r0, #16]

            /* Set thread mode to privileged */
            movs r0, #0
            msr CONTROL, r0
            /* No ISB required on M0 */
            /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */

            ldr r0, FEXC_RETURN_MSP
            bx r0
    .align 4
    FEXC_RETURN_MSP:
      .word 0xFFFFFFF9
        "
        );
    }
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn hard_fault_handler() {
    // If `kernel_stack` is non-zero, then hard-fault occurred in
    // kernel, otherwise the hard-fault occurred in user.
    asm!("
    /*
     * Will be incremented to 1 when we determine that it was a fault
     * in the kernel
     */
    movs r1, #0
    /*
     * r2 is used for testing and r3 is used to store lr
     */
    mov r3, lr

    movs r2, #4
    tst r3, r2
    beq _hardfault_msp

_hardfault_psp:
    mrs r0, psp
    b _hardfault_exit

_hardfault_msp:
    mrs r0, msp
    adds r1, #1

_hardfault_exit:

    b {}    // Branch to the non-naked fault handler.
    bx lr   // If continued function returns, we need to manually branch to
            // link register.
    ",
    sym hard_fault_handler_continued,
    options(noreturn));
}
