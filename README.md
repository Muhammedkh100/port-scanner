# Advanced Port Scanner

A multi-threaded TCP port scanner written in Python. It resolves a target
hostname, scans a configurable range of ports concurrently, identifies
common services, grabs basic banners where possible, and can export the
results to JSON.

## Features

- Multi-threaded scanning (`ThreadPoolExecutor`) for fast results
- Hostname resolution with clear error handling
- Common-port shortcut (`-p common`) or custom ranges/lists (`-p 1-1000`, `-p 80,443,8080`)
- Service name mapping for well-known ports (SSH, HTTP, MySQL, RDP, etc.)
- Lightweight banner grabbing for web and generic TCP services
- JSON export for integration with other tools or reports
- Verbose mode for live progress

## Installation

```bash
git clone https://github.com/<your-username>/port-scanner.git
cd port-scanner
pip install -r requirements.txt
```

> This project only uses the Python standard library, so `requirements.txt`
> is empty / informational — no third-party packages are required.

## Usage

```bash
# Scan the most common ports
python scanner.py example.com -p common

# Scan a port range
python scanner.py 192.168.1.1 -p 1-1000

# Scan specific ports with more threads and verbose output
python scanner.py 10.0.0.1 -p 80,443,8080 -t 200 -v

# Scan everything and export to JSON
python scanner.py scanme.nmap.org -p 1-65535 -o results.json
```

### Options

| Flag              | Description                                      | Default |
|-------------------|---------------------------------------------------|---------|
| `-p`, `--ports`   | Port range: `1-1000`, `80,443`, or `common`       | `common`|
| `-t`, `--threads` | Number of worker threads                          | `100`   |
| `--timeout`       | Connection timeout in seconds                     | `1.0`   |
| `-v`, `--verbose` | Print each open port as it's found                | off     |
| `-o`, `--output`  | Export results to a JSON file                     | none    |

## Example Output

```
============================================================
Port Scanner - Target: scanme.nmap.org (45.33.32.156)
Scan started at: 2026-10-02 18:10:03
============================================================
[*] Scanning 20 ports...

============================================================
SCAN RESULTS
============================================================

[+] Found 2 open port(s):

Port 22/tcp
  State:   open
  Service: SSH
  Banner:  SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13

Port 80/tcp
  State:   open
  Service: HTTP
  Banner:  HTTP/1.1 200 OK

============================================================
Scan completed at: 2026-10-02 18:10:05
============================================================
```

## Disclaimer

This tool is provided **for educational purposes and authorized security
testing only**. Only scan systems and networks you own, or that you have
explicit, written permission to test. Scanning networks without
authorization may be illegal in your jurisdiction (e.g. under the U.S.
Computer Fraud and Abuse Act or similar laws elsewhere). The author
assumes no liability and is not responsible for any misuse or damage
caused by this program.

## License

Released under the [MIT License](LICENSE).
