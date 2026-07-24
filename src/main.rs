pub mod config;
pub mod probes;
pub mod utils;

use std::net::Ipv4Addr;
use tokio::io::{self, AsyncWriteExt};
use futures::stream::{self, StreamExt};
use surge_ping::{Client, Config as PingConfig};

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


    // One shared ICMP client/socket for every host; cloning it is cheap.
    let icmp_client = match Client::new(&PingConfig::default()) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("failed to open icmp socket: {err}");
            return;
        }
    };


    // Stream targets through staged multi-protocol probing with bounded concurrency.
    let mut stdout = io::stdout();
    let mut results = stream::iter(targets)
        .map(|ip| {
            let client = icmp_client.clone();
            probe_stub(client, ip)
        })
        .buffer_unordered(CONCURRENCY);

    // Only alive hosts are printed; dead hosts resolve to `None` and are skipped.
    while let Some(maybe_alive) = results.next().await {
        if let Some(ip) = maybe_alive {
            let _ = stdout.write_all(format!("{ip}\n").as_bytes()).await;
        }
    }
}


/// Run each stage in order and short-circuit as soon as one reports alive.
/// Only the ICMP stage exists so far; later stages plug in the same way.
async fn probe_stub(client: Client, ip: Ipv4Addr) -> Option<Ipv4Addr> {
    if probes::icmp_8::check(&client, ip).await {
        return Some(ip);
    }

    None
}