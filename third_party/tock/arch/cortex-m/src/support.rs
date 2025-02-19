use core::ops::FnOnce;

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[inline(always)]
/// NOP instruction
pub fn nop() {
    unsafe {
        asm!("nop", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[inline(always)]
/// WFI instruction
pub unsafe fn wfi() {
    asm!("wfi", options(nomem, preserves_flags));
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
pub unsafe fn atomic<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // Set PRIMASK
    asm!("cpsid i", options(nomem, nostack));

    let res = f();

    // Unset PRIMASK
    asm!("cpsie i", options(nomem, nostack));
    return res;
}

// Mock implementations for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
/// NOP instruction (mock)
pub fn nop() {
    unimplemented!()
}

#[cfg(not(any(target_arch = "arm", target_os = "none")))]
/// WFI instruction (mock)
pub unsafe fn wfi() {
    unimplemented!()
}

#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe fn atomic<F, R>(_f: F) -> R
where
    F: FnOnce() -> R,
{
    unimplemented!()
}
