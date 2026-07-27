use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rand::random;
use surge_ping::{Client, IcmpPacket, PingIdentifier, PingSequence};

use crate::config::ICMP_TIMEOUT_MS;


/// Send one ICMP echo request to `ip` using the shared `client` socket.
/// Returns `true` if a reply arrives before the configured timeout.
pub async fn check(client: &Client, ip: Ipv4Addr) -> bool {

    // A new Pinger is cheap; it reuses the same underlying socket as `client`.
    let mut pinger = client.pinger(IpAddr::V4(ip), PingIdentifier(random())).await;
    pinger.timeout(Duration::from_millis(ICMP_TIMEOUT_MS));

    let payload = [0u8; 8];

    // Timeout, unreachable, permission error, etc. all count as "dead",
    // but the failure is still printed so it is not silently swallowed.
    let (reply, _rtt) = match pinger.ping(PingSequence(0), &payload).await {
        Ok(reply) => reply,
        Err(err) => {
            // eprintln!("icmp probe error for {ip}: {err}");
            return false;
        }
    };

    matches!(reply, IcmpPacket::V4(_))
}