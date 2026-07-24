use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio::io::{self, AsyncBufReadExt, BufReader};

/// Read, validate, and clean stdin into a deduplicated list of IPv4 targets.
/// Returns `None` if stdin is empty or contains only whitespace.
pub async fn read_targets() -> Option<Vec<Ipv4Addr>> {

    // Read every line from stdin into memory before validating the stream.
    let raw_lines = read_raw_lines().await;


    // Empty or whitespace-only stdin has nothing to probe; signal that upward.
    let has_content = raw_lines.iter().any(|line| !line.trim().is_empty());

    if !has_content {
        return None;
    }

    Some(parse_targets(raw_lines))
}


/// Collect every raw line from stdin, in order, without any filtering yet.
async fn read_raw_lines() -> Vec<String> {
    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();
    let mut raw_lines: Vec<String> = Vec::new();

    while let Ok(Some(line)) = lines.next_line().await {
        raw_lines.push(line);
    }

    raw_lines
}


/// Turn raw stdin lines into a deduplicated list of valid IPv4 targets.
fn parse_targets(raw_lines: Vec<String>) -> Vec<Ipv4Addr> {
    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    let mut targets: Vec<Ipv4Addr> = Vec::new();

    for raw in raw_lines {

        // Cut inline comments starting with '#' and trim surrounding whitespace.
        let without_comment = raw.split('#').next().unwrap_or("").trim();

        if without_comment.is_empty() {
            continue;
        }


        // Remove a leading "http://" or "https://" scheme, then a trailing port.
        let without_scheme = strip_scheme(without_comment);
        let without_port = strip_port(without_scheme);

        // debug: println!("cleaned line: {without_port}");


        // Accept IPv4 only; hostnames and non-IPv4 input are silently skipped.
        let ip: Ipv4Addr = match without_port.parse() {
            Ok(ip) => ip,
            Err(_) => {
                // debug: println!("skipped non-ipv4 target: {without_port}");
                continue;
            }
        };


        // Keep only the first occurrence of each address.
        if seen.insert(ip) {
            // debug: println!("accepted target: {ip}");
            targets.push(ip);
        } else {
            // debug: println!("duplicate target skipped: {ip}");
        }
    }

    targets
}


/// Strip a leading "https://" or "http://" scheme from the input, if present.
fn strip_scheme(input: &str) -> &str {
    input
        .strip_prefix("https://")
        .or_else(|| input.strip_prefix("http://"))
        .unwrap_or(input)
}


/// Strip a trailing ":<port>" suffix from the input, if present.
fn strip_port(input: &str) -> &str {
    match input.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => input,
    }
}