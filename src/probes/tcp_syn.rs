use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};
use rand::RngExt;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::config::TCP_PORTS;
use crate::config::TCP_TIMEOUT_MS;

const TCP_HEADER_LEN: usize = 32;


/// Shared TCP SYN prober. One raw socket for the whole process.
/// Cheap to clone (Arc internally).
#[derive(Clone)]
pub struct Client {
    tx: Arc<Mutex<TransportSender>>,
    pending: Arc<Mutex<HashMap<u16, oneshot::Sender<()>>>>,
}


impl Client {
    /// Open the shared raw TCP socket and spawn the receiver thread.
    pub fn new() -> Result<Self, std::io::Error> {
        let protocol =
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

        let (tx, mut rx) = transport_channel(8192, protocol)?;

        let pending: Arc<Mutex<HashMap<u16, oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_bg = Arc::clone(&pending);

        // Dedicated OS thread owns the receiver for the process lifetime.
        thread::spawn(move || {
            let mut iter = tcp_packet_iter(&mut rx);
            loop {
                match iter.next() {
                    Ok((tcp, _addr)) => {
                        let sport = tcp.get_destination();
                        let flags = tcp.get_flags();

                        // SYN-ACK or RST both prove the host is alive.
                        let alive = (flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0)
                            || (flags & TcpFlags::RST != 0);

                        if !alive {
                            continue;
                        }

                        if let Ok(mut map) = pending_bg.lock() {
                            if let Some(tx) = map.remove(&sport) {
                                let _ = tx.send(());
                            }
                        }
                    }
                    Err(_e) => {
                        // eprintln!("tcp_syn receiver error: {_e}");
                        // keep running; transient errors are common under load
                    }
                }
            }
        });

        Ok(Client {
            tx: Arc::new(Mutex::new(tx)),
            pending,
        })
    }
}


/// Resolve the local IPv4 that will be used as source toward `dst`.
/// UDP connect is a no-op on the wire; it only selects the egress route.
fn local_ipv4_for(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddrV4::new(dst, 9)).ok()?;

    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}


/// Build a minimal TCP SYN segment with common options (MSS/SACK/WScale).
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


/// Emit one SYN per configured port from the shared ephemeral sport.
fn send_syns(tx: &mut TransportSender, src: Ipv4Addr, dst: Ipv4Addr, sport: u16) {
    let mut buf = [0u8; TCP_HEADER_LEN];

    for &dport in &TCP_PORTS {
        let pkt = build_syn(&mut buf, src, dst, sport, dport);
        let _ = tx.send_to(pkt.to_immutable(), IpAddr::V4(dst));
    }
}


/// TCP SYN host discovery (IPv4 only).
/// Uses the shared raw socket; returns true on first SYN-ACK or RST.
pub async fn check(client: &Client, ip: Ipv4Addr) -> bool {
    let src = match local_ipv4_for(ip) {
        Some(s) => s,
        None => {
            // eprintln!("tcp_syn: cannot resolve local src for {ip}");
            return false;
        }
    };

    let sport: u16 = rand::random_range(32768..61000);
    let (notify_tx, notify_rx) = oneshot::channel();

    // Register before sending so we never miss a fast reply.
    {
        let mut map = client.pending.lock().unwrap();
        map.insert(sport, notify_tx);
    }

    // Send under a short lock.
    {
        let mut tx = client.tx.lock().unwrap();
        send_syns(&mut tx, src, ip, sport);
    }

    // Wait for notification or timeout. Fully async, no spawn_blocking.
    let result = timeout(Duration::from_millis(TCP_TIMEOUT_MS), notify_rx).await;

    // Always clean up the pending entry.
    {
        let mut map = client.pending.lock().unwrap();
        map.remove(&sport);
    }

    matches!(result, Ok(Ok(())))
}