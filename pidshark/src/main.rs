use aya::{
    maps::{PerfEventArray, perf::Events},
    programs::RawTracePoint, util::online_cpus,
};
use bytes::BytesMut;
use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use pidshark_common::Process;
use tokio::{signal, task};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pidshark"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut RawTracePoint = ebpf.program_mut("pidshark").unwrap().try_into()?;
    program.load()?;
    program.attach("sched_process_exec")?;

    let mut perf_array = PerfEventArray::try_from(ebpf.take_map("PROCESSES").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let buf = perf_array.open(cpu_id, None)?;
        let mut buf = tokio::io::unix::AsyncFd::with_interest(buf, tokio::io::Interest::READABLE)?;

        task::spawn(async move {
            let mut buffers = std::iter::repeat_with(|| BytesMut::with_capacity(1024))
                .take(10)
                .collect::<Vec<_>>();

            loop {
                let mut guard = buf.readable_mut().await.unwrap();
                loop {
                    let Events { read, lost: _ } =
                        guard.get_inner_mut().read_events(&mut buffers).unwrap();
                    for buf in buffers.iter_mut().take(read) {
                        let ptr = buf.as_ptr() as *const Process;
                        let data = unsafe { ptr.read_unaligned() };
                        info!("PID: {}, PPID: {}", data.pid, data.ppid);
                    }

                    if read != buffers.len() {
                        break;
                    }
                }

                guard.clear_ready();
            }
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
