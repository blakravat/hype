/// Maximum number of hosts probed concurrently across all stages.
pub const CONCURRENCY: usize = 360;
/// Timeout for a single ICMP echo request before the host is considered dead.
pub const ICMP_TIMEOUT_MS: u64 = 600;