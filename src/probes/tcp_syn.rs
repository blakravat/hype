use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use rand::RngExt;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::config::{TCP_PORTS, TCP_TIMEOUT_MS};

const TCP_HEADER_LEN: usize = 32;

/// Fixed public IP used only to resolve a route; never actually contacted.
const LOCAL_IP_ANCHOR: (Ipv4Addr, u16) = (Ipv4Addr::new(1, 1, 1, 1), 80);


/// One outbound SYN job: which host, which cached local source IP, and
/// which ephemeral source port identifies this probe's replies.
struct SynJob {
    dst: Ipv4Addr,
    src: Ipv4Addr,
    sport: u16,
}


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

pub async fn check(client: &Client, ip: Ipv4Addr) -> bool {
    client.check(ip).await
}

/// Owns the raw socket's write half exclusively; pulls jobs off the
/// channel and fires one SYN per configured port for each job.
fn sender_loop(mut tx: TransportSender, jobs: std_mpsc::Receiver<SynJob>) {
    let mut buf = [0u8; TCP_HEADER_LEN];

    while let Ok(job) = jobs.recv() {
        for &dport in &TCP_PORTS {
            let packet = build_syn(&mut buf, job.src, job.dst, job.sport, dport);
            let _ = tx.send_to(packet.to_immutable(), IpAddr::V4(job.dst));
        }
    }
}


/// Owns the raw socket's read half exclusively; matches every inbound
/// SYN-ACK/RST to a pending probe by destination port and wakes it up.
fn receiver_loop(mut rx: TransportReceiver, pending: Arc<DashMap<u16, oneshot::Sender<()>>>) {
    let mut iter = tcp_packet_iter(&mut rx);

    loop {
        let Ok((tcp, _addr)) = iter.next() else {
            continue;
        };

        let flags = tcp.get_flags();
        let alive = (flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0)
            || (flags & TcpFlags::RST != 0);

        if !alive {
            continue;
        }

        if let Some((_, notify)) = pending.remove(&tcp.get_destination()) {
            let _ = notify.send(());
        }
    }
}


/// Build one TCP SYN segment with common options (MSS/SACK/WScale).
fn build_syn(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> MutableTcpPacket<'_> {
    let mut tcp = MutableTcpPacket::new(buf).expect("buffer too small for TCP header");

    tcp.set_source(sport);
    tcp.set_destination(dport);
    tcp.set_sequence(rand::rng().random());
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(8);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(64240);
    tcp.set_urgent_ptr(0);

    tcp.set_options(&[
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ]);

    let csum = ipv4_checksum(&tcp.to_immutable(), &src, &dst);
    tcp.set_checksum(csum);

    tcp
}


/// Resolve the local IPv4 address the OS would use to reach the public
/// internet, computed once and cached on `Client` for the whole run.
/// UDP `connect` only performs a route lookup — no packet is sent.
fn resolve_local_ipv4() -> std::io::Result<Ipv4Addr> {
    let (anchor_ip, anchor_port) = LOCAL_IP_ANCHOR;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddrV4::new(anchor_ip, anchor_port))?;

    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unexpected ipv6 local address",
        )),
    }
}