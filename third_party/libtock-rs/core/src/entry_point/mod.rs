use crate::memop;
use crate::syscalls;
use core::ptr;

// _start and rust_start are the first two procedures executed when a Tock
// application starts. _start is invoked directly by the Tock kernel; it
// performs stack setup then calls rust_start. rust_start performs data
// relocation and sets up the heap before calling the rustc-generated main.
// rust_start and _start are tightly coupled.
//
// The memory layout is controlled by the linker script.
//
// When the kernel gives control to us, we get r0-r3 values that is as follows.
//
//     +--------------+ <- (r2) mem.len()
//     | Grant        |
//     +--------------+
//     | Unused       |
//  S  +--------------+ <- (r3) app_heap_break
//  R  | Heap         |         (hardcoded to mem_start + 3072 in
//  A  +--------------|          Processs::create which could be lesser than
//  M  | .bss         |          mem_start + stack + .data + .bss)
//     +--------------|
//     | .data        |
//     +--------------+
//     | Stack        |
//     +--------------+ <- (r1) mem_start
//
//     +--------------+
//     | .text        |
//  F  +--------------+
//  L  | .crt0_header |
//  A  +--------------+ <- (r0) app_start
//  S  | Protected    |
//  H  | Region       |
//     +--------------+
//
// We want to organize the memory as follows.
//
//     +--------------+ <- app_heap_break
//     | Heap         |
//     +--------------| <- heap_start
//     | .bss         |
//     +--------------|
//     | .data        |
//     +--------------+ <- stack_start (stacktop)
//     | Stack        |
//     | (grows down) |
//     +--------------+ <- mem_start
//
// app_heap_break and mem_start are given to us by the kernel. The stack size is
// determined using pointer app_start, and is used with mem_start to compute
// stack_start (stacktop). The placement of .data and .bss are given to us by
// the linker script; the heap is located between the end of .bss and
// app_heap_break. This requires that .bss is the last (highest-address) section
// placed by the linker script.

#[cfg_attr(target_arch = "riscv32", path = "start_item_riscv32.rs")]
#[cfg_attr(target_arch = "arm", path = "start_item_arm.rs")]
mod start_item;

/// The header encoded at the beginning of .text by the linker script. It is
/// accessed by rust_start() using its app_start parameter.
#[repr(C)]
struct LayoutHeader {
    got_sym_start: usize,
    got_start: usize,
    got_size: usize,
    data_sym_start: usize,
    data_start: usize,
    data_size: usize,
    bss_start: usize,
    bss_size: usize,
    reldata_start: usize,
    stack_size: usize,
}

//Procedural macro to generate a function to read APP_HEAP_SIZE
libtock_codegen::make_read_env_var!("APP_HEAP_SIZE");

/// Rust setup, called by _start. Uses the extern "C" calling convention so that
/// the assembly in _start knows how to call it (the Rust ABI is not defined).
/// Sets up the data segment (including relocations) and the heap, then calls
/// into the rustc-generated main(). This cannot use mutable global variables or
/// global references to globals until it is done setting up the data segment.
#[no_mangle]
unsafe extern "C" fn rust_start(app_start: usize, stacktop: usize, app_heap_start: usize) -> ! {
    extern "C" {
        // This function is created internally by `rustc`. See
        // `src/lang_items.rs` for more details.
        fn main(argc: isize, argv: *const *const u8) -> isize;
    }

    // Copy .data into its final location in RAM (determined by the linker
    // script -- should be immediately above the stack).
    let layout_header: &LayoutHeader = core::mem::transmute(app_start);

    let data_flash_start_addr = app_start + layout_header.data_sym_start;

    ptr::copy_nonoverlapping(
        data_flash_start_addr as *const u8,
        stacktop as *mut u8,
        layout_header.data_size,
    );

    // Zero .bss (specified by the linker script).
    let bss_start = layout_header.bss_start as *mut u8;
    core::ptr::write_bytes(bss_start, 0u8, layout_header.bss_size);

    // TODO: Wait for rustc to have working ROPI-RWPI relocation support, then
    // implement dynamic relocations here. At the moment, rustc does not have
    // working ROPI-RWPI support, and it is not clear what that support would
    // look like at the LLVM level. Once we know what the relocation strategy
    // looks like we can write the dynamic linker.

    // Initialize the heap. Unlike libtock-c's newlib allocator, which can use
    // `sbrk` system call to dynamically request heap memory from the kernel, we
    // need to tell `linked_list_allocator` where the heap starts and ends.
    //
    // We get this from the environment to make it easy to set per compile.
    let app_heap_size: usize = read_APP_HEAP_SIZE();

    let app_heap_end = app_heap_start + app_heap_size;

    // Tell the kernel the new app heap break.
    memop::set_brk(app_heap_end as *const u8);

    #[cfg(feature = "alloc_init")]
    crate::libtock_alloc_init(app_heap_start, app_heap_size);

    main(0, ptr::null());

    loop {
        syscalls::raw::yieldk();
    }
}
