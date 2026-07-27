pub mod config;
pub mod probes;
pub mod utils;

use std::{net::Ipv4Addr, time::Duration};
use futures::stream::{self, StreamExt};
use reqwest::{Client as HttpClient, redirect::Policy};
use surge_ping::{Client as IcmpClient, Config as PingConfig};

use config::CONCURRENCY;
use config::HTTP_TIMEOUT_MS;
use config::HTTP_USER_AGENT;

use utils::input;
use utils::progress::Progress;


#[tokio::main]
async fn main() {

    // Read and validate stdin; show usage and exit if nothing was piped in.
    let targets = match input::read_targets().await {
        Some(targets) => targets,
        None => {
            println!(
                "Usage:\n\
                 - <command> | hype >> output.txt\n\
                 - hype < input.txt >> output.txt\n\
                 - etc."
            );
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

    // One shared HTTP client for every host; connection pooling included.
    let http_client = match HttpClient::builder()
        .user_agent(HTTP_USER_AGENT)
        .timeout(Duration::from_millis(HTTP_TIMEOUT_MS))
        .redirect(Policy::none())
        .tls_danger_accept_invalid_certs(true)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            eprintln!("failed to build http client: {err}");
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
            let http_client = http_client.clone();

            probe_stub(icmp_client, tcp_client, http_client, ip)
        })
        .buffer_unordered(CONCURRENCY);

    // Only alive hosts are printed; dead hosts resolve to `None` and are skipped.
    while let Some(maybe_alive) = results.next().await {
        progress.inc();

        if let Some(ip) = maybe_alive {
            // Hide the bar while printing so the alive-host line lands
            // cleanly above it instead of tearing the bar mid-redraw.
            progress.suspend(|| println!("{ip}"));
        }
    }

    progress.finish();
}


/// Run each stage in order and short-circuit as soon as one reports alive.
/// ICMP runs first; HTTP is the next stage, plugged in the same way.
async fn probe_stub(icmp_client: IcmpClient, tcp_client: probes::tcp_syn::Client, http_client: HttpClient, ip: Ipv4Addr) -> Option<Ipv4Addr> {
    if probes::icmp_8::check(&icmp_client, ip).await {
        return Some(ip);
    }

    if probes::tcp_syn::check(&tcp_client, ip).await {
        return Some(ip);
    }

    if probes::http::check(&http_client, ip).await {
        return Some(ip);
    }

    None
}