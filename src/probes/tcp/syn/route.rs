use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};

/// Fixed public IP used only to resolve a route; never actually contacted.
const LOCAL_IP_ANCHOR: (Ipv4Addr, u16) = (Ipv4Addr::new(1, 1, 1, 1), 80);

/// Resolve the local IPv4 address the OS would use to reach the public
/// internet, computed once and cached on `Client` for the whole run.
/// UDP `connect` only performs a route lookup — no packet is sent.
pub(super) fn resolve_local_ipv4() -> io::Result<Ipv4Addr> {
    let (anchor_ip, anchor_port) = LOCAL_IP_ANCHOR;
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddrV4::new(anchor_ip, anchor_port))?;

    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::Other,
            "unexpected ipv6 local address",
        )),
    }
}