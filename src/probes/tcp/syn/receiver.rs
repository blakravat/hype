use std::sync::Arc;

use dashmap::DashMap;
use pnet::packet::tcp::TcpFlags;
use pnet::transport::{tcp_packet_iter, TransportReceiver};
use tokio::sync::oneshot;

/// Owns the raw socket's read half exclusively; matches every inbound
/// SYN-ACK/RST to a pending probe by destination port and wakes it up.
pub(super) fn receiver_loop(
    mut rx: TransportReceiver,
    pending: Arc<DashMap<u16, oneshot::Sender<()>>>,
) {
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