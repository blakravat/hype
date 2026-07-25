/// Maximum number of hosts probed concurrently across all stages.
pub const CONCURRENCY: usize = 360;

/// Timeout for a single ICMP echo request before the host is considered dead.
pub const ICMP_TIMEOUT_MS: u64 = 600;

/// Timeout for a single HTTP HEAD request before the host is considered dead.
pub const HTTP_TIMEOUT_MS: u64 = 600;

/// User-Agent header sent with every HTTP probe request.
pub const HTTP_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";