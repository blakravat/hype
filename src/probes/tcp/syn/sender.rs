use std::net::IpAddr;
use std::sync::mpsc as std_mpsc;

use pnet::transport::TransportSender;

use super::job::SynJob;
use super::packet::{build_syn, TCP_HEADER_LEN};
use crate::config::TCP_PORTS;

/// Owns the raw socket's write half exclusively; pulls jobs off the
/// channel and fires one SYN per configured port for each job.
pub(super) fn sender_loop(mut tx: TransportSender, jobs: std_mpsc::Receiver<SynJob>) {
    let mut buf = [0u8; TCP_HEADER_LEN];

    while let Ok(job) = jobs.recv() {
        for &dport in &TCP_PORTS {
            let packet = build_syn(&mut buf, job.src, job.dst, job.sport, dport);
            let _ = tx.send_to(packet.to_immutable(), IpAddr::V4(job.dst));
        }
    }
}