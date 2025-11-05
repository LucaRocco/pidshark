use std::{mem::MaybeUninit, time::Duration};

use plain::Plain;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use tokio::{signal, task};
use tokio_util::sync::CancellationToken;

mod exec {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/exec.skel.rs"));
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Event {
    pid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    command: [u8; 16],
}

unsafe impl Plain for Event {}

fn process_data(data: &[u8]) -> i32 {
    let s = plain::from_bytes::<Event>(data).unwrap();
    let end = s
        .command
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(s.command.len());
    println!(
        "{}  {}  {}  {}  {}",
        s.pid,
        s.tid,
        s.uid,
        s.gid,
        String::from_utf8_lossy(&s.command[..end])
    );

    return 0;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let skel_builder = exec::ExecSkelBuilder::default();

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.PROCESSES, |data| process_data(data))
        .expect("failed to add ringbuf");
    let ringbuf = builder.build().unwrap();

    let () = skel.attach()?;

    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();

    let handle = task::spawn_blocking(move || {
        println!(" PID  TID  UID  GID  COMMAND");

        while !cancel_child.is_cancelled() {
            ringbuf.poll_raw(Duration::from_millis(500));
        }
    });

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");
    cancel.cancel();
    handle.await.ok();
    Ok(())
}
