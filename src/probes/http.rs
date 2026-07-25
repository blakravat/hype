use std::net::Ipv4Addr;

use reqwest::{Client, StatusCode};

/// Probe `ip` over HTTP (port 80) and HTTPS (port 443, certificate
/// verification disabled) at the same time; whichever answers first with
/// an "alive" status wins. Only when neither one reaches the host at all
/// is the target reported dead.
pub async fn check(client: &Client, ip: Ipv4Addr) -> bool {
    let http_url = format!("http://{ip}");
    let https_url = format!("https://{ip}");

    let http = try_request(client, &http_url, ip);
    let https = try_request(client, &https_url, ip);

    tokio::pin!(http);
    tokio::pin!(https);

    let mut http_done = false;
    let mut https_done = false;

    loop {
        tokio::select! {
            result = &mut http, if !http_done => {
                http_done = true;
                if result.unwrap_or(false) {
                    return true;
                }
            }
            result = &mut https, if !https_done => {
                https_done = true;
                if result.unwrap_or(false) {
                    return true;
                }
            }
        }

        if http_done && https_done {
            return false;
        }
    }
}


/// Send one HEAD request to `url`. Returns `None` on a network-level
/// failure, or `Some` with whether the response status counts as "alive".
async fn try_request(client: &Client, url: &str, ip: Ipv4Addr) -> Option<bool> {
    match client.head(url).send().await {
        Ok(response) => Some(is_alive_status(response.status())),
        Err(err) => {
            eprintln!("http probe error for {ip} ({url}): {err}");
            None
        }
    }
}


/// 1xx through 5xx all mean the server answered; only a connection-level
/// failure (handled separately as `Err`) counts as dead.
fn is_alive_status(status: StatusCode) -> bool {
    status.is_informational()
        || status.is_success()
        || status.is_redirection()
        || status.is_client_error()
        || status.is_server_error()
}