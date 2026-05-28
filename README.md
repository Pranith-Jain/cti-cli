# cti-cli

Command-line threat intelligence powered by [pranithjain.qzz.io](https://pranithjain.qzz.io).

13+ live feeds · AI copilot · 24+ IOC enrichment providers · ransomware tracking · CVE lookup · actor KB.

## Install

```bash
pip install git+https://github.com/Pranith-Jain/cti-cli.git
```

Or clone and install:

```bash
git clone https://github.com/Pranith-Jain/cti-cli.git
cd cti-cli
pip install .
```

## Usage

```bash
# AI investigation on any indicator
cti investigate 8.8.8.8
cti investigate CVE-2024-1709
cti investigate LockBit
cti investigate <sha256>

# Search across 12+ threat intel sources
cti search "Cobalt Strike"

# Check an IOC against 24+ providers
cti check 185.234.72.0

# Hash lookup with enrichment
cti hash-lookup <sha256>

# CVE lookup — CVSS, EPSS, KEV
cti cve CVE-2024-1709

# Recent ransomware activity
cti ransomware
cti ransomware --group lockbit

# Threat actor lookup
cti actor "Scattered Spider"

# IP geolocation
cti ip 8.8.8.8

# Domain lookup — WHOIS, DNS, email auth
cti domain example.com

# Extract IOCs from text or file
echo "some text with 185.234.72.0 and CVE-2024-1709" | cti extract
cti extract --file report.txt

# Feed health status
cti feed-status

# Recent threat briefings
cti briefings
```

All commands support `--json` for raw JSON output:

```bash
cti investigate 8.8.8.8 --json
cti ransomware --json
```

## Commands

| Command | Description |
|---------|-------------|
| `investigate` | AI investigation on any indicator (IP, domain, hash, CVE, actor, keyword) |
| `search` | Search across 12+ threat intel sources |
| `check` | Check IOC against 24+ enrichment providers (streaming) |
| `hash-lookup` | Hash enrichment — VirusTotal, MalwareBazaar, MalShare, OTX |
| `cve` | CVE lookup — CVSS, EPSS, KEV, affected products |
| `ransomware` | Recent ransomware victims and groups |
| `actor` | Threat actor lookup — TTPs, victims, CVEs |
| `ip` | IP geolocation — country, ASN, ISP, proxy flags |
| `domain` | Domain lookup — WHOIS, DNS, email auth, CT logs |
| `extract` | Extract IOCs from text or file |
| `briefings` | Recent threat briefings |
| `feed-status` | Health status of all live feeds |
| `copilot` | Alias for investigate |

## API

This CLI calls the public API at `https://pranithjain.qzz.io/api/v1/`. No API key required. Rate-limited to 30 req/min.

## License

MIT
