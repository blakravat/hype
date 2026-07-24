pub mod config;
pub mod probes;
pub mod utils;

use std::net::Ipv4Addr;
use tokio::io::{self, AsyncWriteExt};
use futures::stream::{self, StreamExt};

use config::CONCURRENCY;
use utils::input;


#[tokio::main]
async fn main() {

    // Read and validate stdin; show usage and exit if nothing was piped in.
    let targets = match input::read_targets().await {
        Some(targets) => targets,
        None => {
            println!("Usage: <target> | hype");
            return;
        }
    };


    // Stream targets through staged multi-protocol probing with bounded concurrency.
    let mut stdout = io::stdout();
    let mut results = stream::iter(targets)
        .map(probe_stub)
        .buffer_unordered(CONCURRENCY);

    // Only alive hosts are printed; dead hosts resolve to `None` and are skipped.
    while let Some(maybe_alive) = results.next().await {
        if let Some(ip) = maybe_alive {
            let _ = stdout.write_all(format!("{ip}\n").as_bytes()).await;
        }
    }
}


/// Placeholder for staged multi-protocol probing (ICMP -> TCP -> UDP -> HTTP).
/// Each stage will short-circuit with `Some(ip)` as soon as the host is found
/// alive; `None` means every stage reported the host dead.
async fn probe_stub(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    Some(ip)
}