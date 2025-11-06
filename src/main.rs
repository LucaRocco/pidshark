use std::{mem::MaybeUninit, time::Duration};

use plain::Plain;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use tokio::{signal, task};
use tokio_util::sync::CancellationToken;

mod processes_trace {
    include!(concat!(env!("OUT_DIR"), "/processes_trace.skel.rs"));
}

mod common {
    #![allow(non_camel_case_types)]
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}

unsafe impl Plain for common::process {}

fn process_data(data: &[u8]) -> i32 {
    let s = common::process::from_bytes(data).unwrap();
    println!(
        "{}  {}  {}  {}  {:?}",
        s.pid,
        s.tid,
        s.user,
        s.group,
        String::from_utf8_lossy(s.command.as_slice())
    );

    return 0;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let skel_builder = processes_trace::ProcessesTraceSkelBuilder::default();

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
