use std::net::Ipv4Addr;

/// One outbound SYN job: which host, which cached local source IP, and
/// which ephemeral source port identifies this probe's replies.
pub(super) struct SynJob {
    pub(super) dst: Ipv4Addr,
    pub(super) src: Ipv4Addr,
    pub(super) sport: u16,
}