#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{map, raw_tracepoint},
    maps::PerfEventArray,
    programs::RawTracePointContext,
};
use aya_log_ebpf::info;
use pidshark_common::Process;

use crate::vmlinux::task_struct;

#[rustfmt::skip]
mod vmlinux;

#[map]
static PROCESSES: PerfEventArray<Process> = PerfEventArray::new(0);

#[raw_tracepoint]
pub fn pidshark(ctx: RawTracePointContext) -> i32 {
    match unsafe { try_pidshark(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_pidshark(ctx: RawTracePointContext) -> Result<i32, i32> {
    let (pid, ppid) = unsafe {
        let task: *const task_struct = ctx.arg(0);
        let read_result = bpf_probe_read_kernel(&(*task).pid);

        if read_result.is_err() {
            return Err(1);
        }

        let parent = bpf_probe_read_kernel(&(*task).parent);
        if parent.is_err() {
            return Err(1);
        }

        let ppid_read_result = bpf_probe_read_kernel(&(*parent.unwrap()).pid);

        if ppid_read_result.is_err() {
            return Err(1);
        }

        (read_result.unwrap(), ppid_read_result.unwrap())
    };

    PROCESSES.output(&ctx, &Process { pid, ppid }, 0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
