use std::{mem::MaybeUninit, time::Duration};

use anyhow::Ok;
use plain::Plain;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use tokio::{signal, sync::mpsc::channel, task};
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let skel_builder = processes_trace::ProcessesTraceSkelBuilder::default();

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;

    let (sender, mut receiver) = channel(1024);
    let sender_clone = sender.clone();
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.PROCESSES, move |data| {
            let s = common::process::from_bytes(data).unwrap();
            if let Err(e) = sender.try_send(*s) {
                eprintln!("Ringbuf channel full or closed: {:?}", e);
            }

            0
        })
        .expect("failed to add processes ringbuf")
        .add(&skel.maps.FORKS, move |data| {
            let s = common::process::from_bytes(data).unwrap();
            if let Err(e) = sender_clone.try_send(*s) {
                eprintln!("Ringbuf channel full or closed: {:?}", e);
            }

            0
        })
        .expect("failed to add forks ringbuf");
    let ringbuf = builder.build().unwrap();

    let () = skel.attach()?;

    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    let receiver_child = cancel.clone();

    let exec_ringbug_poller = task::spawn_blocking(move || {
        while !cancel_child.is_cancelled() {
            ringbuf.poll_raw(Duration::from_millis(500));
        }
    });

    let processes_receiver = task::spawn_blocking(move || {
        println!("EVENT\tPID\tNS_PID\tTID\tNS_TID\tUID\tGID\tSTART_TIME\tCOMMAND");

        while !receiver_child.is_cancelled() {
            let process = receiver.blocking_recv();
            if process.is_none() {
                continue;
            }

            let process = process.unwrap();
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}",
                if process.event_type == 1 {
                    "EXEC"
                } else if process.event_type == 2 {
                    "FORK"
                } else {
                    "EXIT"
                },
                process.pid,
                process.ns_pid,
                process.tid,
                process.ns_tid,
                process.uid,
                process.gid,
                process.start_time,
                String::from_utf8_lossy(process.command.as_slice())
            );
        }
    });

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    cancel.cancel();
    let poller_stop = exec_ringbug_poller.await;
    if poller_stop.is_err() {
        panic!("could not stop poller")
    }
    let receiver_stop = processes_receiver.await;
    if receiver_stop.is_err() {
        panic!("could not stop receiver")
    }

    Ok(())
}
