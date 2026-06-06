# Reality Finder

Find suitable Reality protocol dest domains by scanning nearby IP ranges and verifying TLS compatibility.

Based on [RealiTLScanner](https://github.com/xtls/RealiTLScanner) and [RealityChecker](https://github.com/V2RaySSR/RealityChecker), rewritten in Python as a unified tool.

## Quick Start

No installation needed:

```bash
uvx reality-finder find -addr <YOUR_VPS_IP> -n 10 -thread 10 -timeout 5
```

> Requires [uv](https://docs.astral.sh/uv/)

### Example Output

```
            Reality Finder — finding 10 suitable dests
Rating Domain                       Handshake Validity CDN  Hot
─────────────────────────────────────────────────────────────────
★★★    example1.com                      43ms     89d   -    -
★★★    example2.com                      72ms     62d   -    -
★★     example3.com                      85ms     59d  Med   -
★      example4.com                     120ms     71d   -   Yes

  342 scanned · 28 feasible · 10 passed · 45.2s

  ★★★ Recommended  ★★ Usable (CDN detected)  ★ Use with caution (popular site)
```

## Installation (Optional)

Install as a persistent tool:

```bash
uv tool install reality-finder
```

Or from source:

```bash
git clone https://github.com/huanglune/reality-finder
cd reality-finder
uv sync
uv run reality-finder find -addr <VPS_IP> -n 10
```

## Usage

### `find` — Scan + Verify (Recommended)

```bash
# Scan outward from your VPS IP, stop after finding 10 suitable domains
uvx reality-finder find -addr <VPS_IP> -n 10

# Find 5, with 20 concurrent workers
uvx reality-finder find -addr <VPS_IP> -n 5 -thread 20 -timeout 5

# Scan a specific CIDR range
uvx reality-finder find -addr <VPS_IP>/24 -n 10

# Save results to file
uvx reality-finder find -addr <VPS_IP> -n 10 -out result.txt

# Verbose: show why domains failed
uvx reality-finder -v find -addr <VPS_IP> -n 10
```

### What should `-addr` be?

**Your VPS IP.** Reality protocol requires your proxy to perform a TLS handshake with the dest server. The closer the dest is (same datacenter/subnet), the lower the latency. The tool automatically scans outward from your IP to find nearby candidates.

### `scan` — Scan Only

Raw TLS scan without verification, outputs CSV.

```bash
uvx reality-finder scan -addr <IP>/24 -thread 10 -timeout 5 -out raw.csv
```

### `check` — Verify Only

Deep-check known domains without scanning.

```bash
uvx reality-finder check -d example.com
uvx reality-finder check -csv raw.csv
uvx reality-finder check -f domains.txt
```

## How It Works

Scans IP ranges for TLS 1.3 + H2 endpoints, then verifies each candidate through a multi-stage pipeline: GFW blocklist, GeoIP, TLS 1.3, X25519, HTTP/2, SNI match, certificate validity, CDN detection, and popular website detection. Domains that fail hard requirements are excluded; CDN and popularity are flagged but not excluded.

## GeoIP (Optional)

Download Country.mmdb to enable geographic filtering (auto-excludes domestic IPs):

```bash
wget -O Country.mmdb https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb
```

## Notes

- **Run locally** — Scanning from cloud VPS may get the IP flagged
- **Auto-stop** — Stops once `-n` suitable domains are found

## Credits

- [RealiTLScanner](https://github.com/xtls/RealiTLScanner)
- [RealityChecker](https://github.com/V2RaySSR/RealityChecker)
- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)

## License

GPL-3.0
