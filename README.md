# HYPE - Fast Multi-Protocol Host Discovery

**HYPE** (a play on **Hi IP**) is a high-performance **host discovery** tool written in **Rust**. HYPE "says Hi" to every IP address to determine host availability through multiple probing methods.

## Features

* **Multi-protocol probing** 
    - ICMP Echo (Type 8)
    - TCP SYN across common ports (80, 443, 22, 445, 3389)
* **Staged discovery**
    - probes run in order and short-circuit on the first positive response
* **High concurrency**
    - bounded concurrent probing (default 600) for fast large-scale scans
* **Progress feedback**
    - live progress bar on stderr; alive hosts printed to stdout
* **IPv4 focused**
    - lightweight and optimized for IPv4 target lists
* **Simple pipeline-friendly design**
    - reads targets from stdin, outputs only alive IPs

## Usage

HYPE requires **root privileges**.

### Option 1: Binary release

Download the latest binary from the [Releases](https://github.com/blakravat/hype/releases) page, then:

```bash
# From a pipe
cat targets.txt | sudo ./hype > alive.txt

# Or redirect input
sudo ./hype < targets.txt > alive.txt
```

### Option 2: Build from source

Requirements: Rust toolchain (edition 2024+).

```bash
git clone https://github.com/blakravat/hype.git
cd hype
cargo build --release

# Run the optimized binary
cat targets.txt | sudo ./target/release/hype > alive.txt
```

**Notes**
- Input: one IPv4 address per line (stdin)
- Output: only alive hosts (stdout), one IP per line
- Progress bar is written to stderr so it does not pollute the results file

## License

HYPE is released under MIT license. See [LICENSE](https://github.com/blakravat/hype/blob/main/LICENSE).