use std::net::Ipv4Addr;

use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpOption};
use rand::RngExt;

/// Full TCP header length with the options set below (20-byte base header
/// + 12 bytes of options, padded to a multiple of 4 -> data_offset = 8).
pub(super) const TCP_HEADER_LEN: usize = 32;

/// Build one TCP SYN segment with common options (MSS/SACK/WScale).
pub(super) fn build_syn(
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