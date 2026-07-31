pub mod config;
pub mod probes;
pub mod utils;

use std::{net::Ipv4Addr};
use futures::stream::{self, StreamExt};
use surge_ping::{Client as IcmpClient, Config as PingConfig};

use config::CONCURRENCY;
use config::PRINT_BATCH;

use utils::input;
use utils::progress::Progress;


#[tokio::main]
async fn main() {
    // Print command usage and execution requirements.
    let usage = || {
        println!(
            "Usage:\n\
             - <command> | sudo hype > output.txt\n\
             - sudo hype < input.txt > output.txt\n\
             - etc.\n\
             \n\
             Note:\n\
             - This program must be run as root (sudo)."
        );
    };

    // Raw sockets require root privileges.
    if unsafe { libc::geteuid() } != 0 {
        usage();
        std::process::exit(1);
    }

    // Read and validate stdin; show usage and exit if nothing was piped in.
    let targets = match input::read_targets().await {
        Some(targets) => targets,
        None => {
            usage();
            return;
        }
    };


    // One shared ICMP client/socket for every host; cloning it is cheap.
    let icmp_client = match IcmpClient::new(&PingConfig::default()) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("failed to open icmp socket: {err}");
            return;
        }
    };

    // One shared TCP SYN raw socket + background receiver thread.
    let tcp_client = match probes::tcp_syn::Client::new() {
        Ok(client) => client,
        Err(err) => {
            eprintln!("failed to open tcp syn socket: {err}");
            return;
        }
    };


    // Single global progress bar for the whole run (drawn on stderr).
    let progress = Progress::new(targets.len() as u64);


    // Stream targets through staged multi-protocol probing with bounded concurrency.
    let mut results = stream::iter(targets)
        .map(|ip| {
            let icmp_client = icmp_client.clone();
            let tcp_client = tcp_client.clone();

            probe_stub(icmp_client, tcp_client, ip)
        })
        .buffer_unordered(CONCURRENCY);

    // Buffer alive hosts to reduce progress bar suspend/redraw frequency.
    let mut alive_batch = Vec::with_capacity(PRINT_BATCH);

    // Only alive hosts are printed; dead hosts resolve to `None` and are skipped.
    while let Some(maybe_alive) = results.next().await {
        progress.inc();

        if let Some(ip) = maybe_alive {
            alive_batch.push(ip);

            if alive_batch.len() >= PRINT_BATCH {
                // Hide the bar while printing so the alive-host line lands
                // cleanly above it instead of tearing the bar mid-redraw.
                progress.suspend(|| {
                    for ip in alive_batch.drain(..) {
                        println!("{ip}");
                    }
                });
            }
        }
    }

    // Flush any remaining alive hosts.
    if !alive_batch.is_empty() {
        progress.suspend(|| {
            for ip in alive_batch.drain(..) {
                println!("{ip}");
            }
        });
    }

    progress.finish();
}


/// Run each stage in order and short-circuit as soon as one reports alive.
/// ICMP runs first; HTTP is the next stage, plugged in the same way.
async fn probe_stub(icmp_client: IcmpClient, tcp_client: probes::tcp_syn::Client, ip: Ipv4Addr) -> Option<Ipv4Addr> {
    if probes::icmp_8::check(&icmp_client, ip).await {
        return Some(ip);
    }

    if probes::tcp_syn::check(&tcp_client, ip).await {
        return Some(ip);
    }

    None
}