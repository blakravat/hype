use std::net::Ipv4Addr;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::job::SynJob;
use super::receiver::receiver_loop;
use super::route::resolve_local_ipv4;
use super::sender::sender_loop;
use crate::config::TCP_TIMEOUT_MS;

/// Shared TCP SYN prober. One raw socket, one dedicated sender thread,
/// one dedicated receiver thread, for the whole process — `Client` is
/// just a cheap handle (channel sender + concurrent map + cached IP).
#[derive(Clone)]
pub struct Client {
    jobs: std_mpsc::Sender<SynJob>,
    pending: Arc<DashMap<u16, oneshot::Sender<()>>>,
    local_ip: Ipv4Addr,
}

impl Client {
    /// Open the shared raw socket, resolve+cache the local source IP once,
    /// and spawn the dedicated sender and receiver threads.
    pub fn new() -> std::io::Result<Self> {
        let protocol =
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let (tx, rx) = transport_channel(8192, protocol)?;

        let local_ip = resolve_local_ipv4()?;
        let pending: Arc<DashMap<u16, oneshot::Sender<()>>> = Arc::new(DashMap::new());

        let (job_tx, job_rx) = std_mpsc::channel::<SynJob>();

        // Dedicated sender thread: the only place that ever touches `tx`.
        thread::spawn(move || sender_loop(tx, job_rx));

        // Dedicated receiver thread: the only place that ever touches `rx`.
        let pending_bg = Arc::clone(&pending);
        thread::spawn(move || receiver_loop(rx, pending_bg));

        Ok(Client { jobs: job_tx, pending, local_ip })
    }

    /// TCP SYN host discovery (IPv4 only). Returns true on the first
    /// SYN-ACK or RST received for any of the configured ports.
    pub async fn check(&self, ip: Ipv4Addr) -> bool {
        let sport: u16 = rand::random_range(32768..61000);
        let (notify_tx, notify_rx) = oneshot::channel();

        // Register before sending so a fast reply is never missed.
        self.pending.insert(sport, notify_tx);

        let sent = self
            .jobs
            .send(SynJob { dst: ip, src: self.local_ip, sport })
            .is_ok();

        let alive = sent
            && matches!(
                timeout(Duration::from_millis(TCP_TIMEOUT_MS), notify_rx).await,
                Ok(Ok(()))
            );

        self.pending.remove(&sport);
        alive
    }
}

/// TCP SYN host discovery (IPv4 only). Returns true on the first
/// SYN-ACK or RST received for any of the configured ports. Thin wrapper
/// so callers use `probes::tcp_syn::check(&client, ip)`, matching the
/// calling convention of `probes::icmp_8::check` and `probes::http::check`.
pub async fn check(client: &Client, ip: Ipv4Addr) -> bool {
    client.check(ip).await
}