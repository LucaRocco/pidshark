use anyhow::Ok;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::{mem::MaybeUninit, time::Duration};
use tokio::{signal, sync::mpsc::channel, task};
use tokio_util::sync::CancellationToken;
use zerocopy::TryFromBytes;

pub mod models;

mod processes_trace {
    include!(concat!(env!("OUT_DIR"), "/processes_trace.skel.rs"));
}

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
        .add(&skel.maps.EXECS, move |data| {
            let s = common::process::from_bytes(data).unwrap();
            if let Err(e) = sender.try_send(*s) {
                eprintln!("Ringbuf channel full or closed: {:?}", e);
            }

            0
        })
        .expect("failed to add processes ringbuf")
        .add(&skel.maps.FORKS, move |data| {
            let process = models::process::Process::try_ref_from_bytes(data).unwrap();
            if let Err(e) = sender_clone.try_send(*process) {
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
        println!("EVENT\tPID\tP_PID\tNS_PID\tTID\tNS_TID\tUID\tGID\tSTART_TIME\tCOMMAND");

        while !receiver_child.is_cancelled() {
            let process = receiver.blocking_recv();
            if process.is_none() {
                continue;
            }

            let process = process.unwrap();
            let j = serde_json::to_string(&process).unwrap();

            println!("{}", j)
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
