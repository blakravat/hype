/// Maximum number of hosts probed concurrently across all stages.
pub const CONCURRENCY: usize = 600;

/// Number of alive hosts buffered before printing.
pub const PRINT_BATCH: usize = 100;

/// Timeout for a single ICMP echo request before the host is considered dead.
pub const ICMP_TIMEOUT_MS: u64 = 600;

/// TCP ports probed during SYN host discovery.
pub const TCP_PORTS: [u16; 5] = [80, 443, 22, 445, 3389];

/// Maximum time to wait for a SYN-ACK or RST response.
pub const TCP_TIMEOUT_MS: u64 = 600;

/// Timeout for a single HTTP HEAD request before the host is considered dead.
pub const HTTP_TIMEOUT_MS: u64 = 600;
/// User-Agent header sent with every HTTP probe request.
pub const HTTP_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";