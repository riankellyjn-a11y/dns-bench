# dns-bench

**Fast DNS benchmark and diagnostic tool.** Zero dependencies. Single file. Tests 30+ public DNS servers from YOUR network.

Find the fastest, most reliable DNS for gaming, privacy, or general use in under 30 seconds.

```
python3 dns-bench.py
```

## Why?

Generic "best DNS" recommendations are meaningless. The fastest DNS depends on your ISP, your location, and your network path. This tool tests every major public DNS resolver from your actual machine and tells you which one is fastest **for you**.

## Features

- **30+ DNS servers** tested in parallel (Cloudflare, Google, Quad9, OpenDNS, AdGuard, and more)
- **Zero dependencies** - pure Python 3.7+, no pip install
- **Gaming mode** - weighted scoring that prioritizes latency + jitter consistency
- **Privacy mode** - filter to privacy-focused resolvers only
- **Family mode** - filter to family-safe DNS with content filtering
- **NXDOMAIN hijack detection** - flags servers that redirect failed lookups
- **Beautiful terminal output** with color-coded grades
- **JSON & Markdown export** for sharing results
- **Cross-platform** - Linux, macOS, Windows

## Quick Start

```bash
# Download and run (no install needed)
curl -sO https://raw.githubusercontent.com/riankellyjn-a11y/dns-bench/main/dns-bench.py
python3 dns-bench.py
```

## Usage

```bash
# Full benchmark (30 servers, 10 rounds each)
python3 dns-bench.py

# Gaming mode - find the lowest latency + jitter DNS
python3 dns-bench.py --gaming

# Quick test (3 rounds - faster but less accurate)
python3 dns-bench.py --fast

# Privacy-focused servers only
python3 dns-bench.py --privacy

# Family-safe DNS only
python3 dns-bench.py --family

# Security-focused servers
python3 dns-bench.py --security

# Show only top 5 results
python3 dns-bench.py --top 5

# Export as JSON (for scripts)
python3 dns-bench.py --json > results.json

# Export as Markdown (for sharing)
python3 dns-bench.py --markdown > results.md

# Custom rounds and timeout
python3 dns-bench.py --rounds 20 --timeout 3
```

## Scoring

### Gaming Score
| Factor | Weight | Why |
|--------|--------|-----|
| Latency | 40% | Raw speed for DNS resolution |
| Jitter | 30% | Consistency matters for matchmaking |
| Reliability | 20% | Server uptime and response rate |
| NXDOMAIN Integrity | 10% | Honest error responses for game anti-cheat |

### Overall Score
| Factor | Weight | Why |
|--------|--------|-----|
| Latency | 30% | General speed |
| Jitter | 20% | Consistency |
| Reliability | 35% | Uptime is king for daily use |
| NXDOMAIN Integrity | 15% | Honest DNS matters |

### Grades
| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 90-100 | Excellent - top tier for your network |
| A | 80-89 | Great - highly recommended |
| B | 70-79 | Good - solid choice |
| C | 60-69 | OK - room for improvement |
| D | 50-59 | Below average |
| F | <50 | Poor - consider alternatives |

## What is NXDOMAIN Hijacking?

Some DNS providers redirect non-existent domain queries to their own servers instead of returning a proper error (NXDOMAIN). This can break applications, interfere with game anti-cheat systems, and is generally considered dishonest behavior. Servers that hijack NXDOMAIN are flagged with `HJ` in the results.

[Learn more about NXDOMAIN hijacking](https://publicdns.info/guides/nxdomain-hijacking.html)

## After Choosing Your DNS

1. Set the recommended DNS on your device or router
2. Flush your DNS cache: `ipconfig /flushdns` (Windows) or `sudo dscacheutil -flushcache` (macOS)
3. For setup guides on every platform: [publicdns.info/guides.html](https://publicdns.info/guides.html)

## Web Version

Prefer a browser-based tool? Use the web benchmark at [publicdns.info/dns-gaming-benchmark.html](https://publicdns.info/dns-gaming-benchmark.html) - tests DNS latency directly from your browser with the same scoring methodology.

## How It Works

1. Sends real DNS queries (A records) to each server for common domains
2. Measures round-trip time with `time.perf_counter()` precision
3. Runs multiple rounds to calculate average, min, max, and jitter (standard deviation)
4. Tests NXDOMAIN handling with random non-existent domains
5. All tests run in parallel using thread pools for speed

No data leaves your machine beyond the DNS queries themselves.

## License

MIT

## Author

**Rian Kelly** - IT Consultant, Dublin, Ireland
- GitHub: [@riankellyjn-a11y](https://github.com/riankellyjn-a11y)
- Web: [publicdns.info](https://publicdns.info)
