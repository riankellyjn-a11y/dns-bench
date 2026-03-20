#!/usr/bin/env python3
"""
dns-bench - Fast DNS Benchmark & Diagnostic Tool
Zero dependencies. Single file. Works everywhere Python 3.7+ exists.

Tests 29 public DNS servers from YOUR network, measures latency, jitter,
reliability, detects NXDOMAIN hijacking, and finds the fastest DNS for
gaming, privacy, or general use.

Usage:
    python3 dns-bench.py              # Full benchmark
    python3 dns-bench.py --gaming     # Gaming-optimized (latency + jitter weighted)
    python3 dns-bench.py --privacy    # Privacy audit mode
    python3 dns-bench.py --fast       # Quick test (3 rounds instead of 10)
    python3 dns-bench.py --json       # Output JSON for scripts/sharing
    python3 dns-bench.py --markdown   # Output shareable markdown

Author: Rian Kelly (https://github.com/riankellyjn-a11y)
License: MIT
Web version: https://publicdns.info/dns-gaming-benchmark.html
"""

import socket
import struct
import time
import sys
import json
import random
import argparse
import concurrent.futures
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple
from statistics import mean, stdev

__version__ = "1.0.0"

# ─── DNS Servers ────────────────────────────────────────────────────────────────

DNS_SERVERS = [
    # Provider, Primary IP, Secondary IP, Category tags
    ("Cloudflare", "1.1.1.1", "1.0.0.1", ["fast", "privacy", "gaming"]),
    ("Cloudflare Family", "1.1.1.3", "1.0.0.3", ["family", "privacy"]),
    ("Cloudflare Malware", "1.1.1.2", "1.0.0.2", ["security", "privacy"]),
    ("Google", "8.8.8.8", "8.8.4.4", ["fast", "gaming", "reliable"]),
    ("Quad9", "9.9.9.9", "149.112.112.112", ["security", "privacy"]),
    ("Quad9 Unsecured", "9.9.9.10", "149.112.112.10", ["fast"]),
    ("OpenDNS", "208.67.222.222", "208.67.220.220", ["security", "reliable"]),
    ("OpenDNS Family", "208.67.222.123", "208.67.220.123", ["family", "security"]),
    ("AdGuard", "94.140.14.14", "94.140.15.15", ["adblock", "privacy"]),
    ("AdGuard Family", "94.140.14.15", "94.140.15.16", ["family", "adblock"]),
    ("CleanBrowsing Security", "185.228.168.9", "185.228.169.9", ["security"]),
    ("CleanBrowsing Family", "185.228.168.168", "185.228.169.168", ["family", "security"]),
    ("CleanBrowsing Adult", "185.228.168.10", "185.228.169.11", ["family"]),
    ("Comodo Secure", "8.26.56.26", "8.20.247.20", ["security"]),
    ("Neustar/Verisign", "64.6.64.6", "64.6.65.6", ["reliable"]),
    ("Level3", "4.2.2.1", "4.2.2.2", ["reliable"]),
    ("DNS.Watch", "84.200.69.80", "84.200.70.40", ["privacy"]),
    ("Yandex", "77.88.8.8", "77.88.8.1", ["fast"]),
    ("Yandex Safe", "77.88.8.88", "77.88.8.2", ["security"]),
    ("Yandex Family", "77.88.8.7", "77.88.8.3", ["family"]),
    ("Mullvad", "194.242.2.2", None, ["privacy"]),
    ("Control D", "76.76.2.0", "76.76.10.0", ["fast", "privacy"]),
    ("NextDNS", "45.90.28.0", "45.90.30.0", ["privacy", "adblock"]),
    ("AliDNS", "223.5.5.5", "223.6.6.6", ["fast"]),
    ("Freenom World", "80.80.80.80", "80.80.81.81", ["fast"]),
    ("Hurricane Electric", "74.82.42.42", None, ["reliable"]),
    ("puntCAT", "109.69.8.51", None, ["privacy"]),
    ("LibreDNS", "116.202.176.26", None, ["privacy"]),
    ("CIRA Shield", "149.112.121.10", "149.112.122.10", ["security", "privacy"]),
]

# ─── ANSI Colors ────────────────────────────────────────────────────────────────

class C:
    """ANSI color codes - degrades gracefully on Windows."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    WHITE = "\033[97m"
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")

# Disable colors if not a TTY or on Windows without ANSI support
if not sys.stdout.isatty():
    C.disable()

# ─── DNS Query Builder ──────────────────────────────────────────────────────────

def build_dns_query(domain: str, qtype: int = 1) -> Tuple[bytes, int]:
    """Build a raw DNS query packet. No dependencies needed."""
    tid = random.randint(0, 65535)
    flags = 0x0100  # Standard query, recursion desired
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)

    # Strip trailing dot (FQDN notation) and validate
    domain = domain.rstrip(".")
    if not domain:
        raise ValueError("Empty domain name")
    labels = domain.split(".")
    question = b""
    for label in labels:
        if not label:
            raise ValueError(f"Empty label in domain: {domain!r}")
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError:
            try:
                encoded = label.encode("idna")
            except (UnicodeError, UnicodeDecodeError):
                raise ValueError(f"Cannot encode DNS label: {label!r}")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label!r} ({len(encoded)} > 63)")
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"
    if len(question) > 255:
        raise ValueError(f"Domain wire format too long: {len(question)} > 255 bytes")
    question += struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN

    return header + question, tid


def parse_dns_response(data: bytes, expected_tid: int) -> Tuple[int, bool]:
    """Parse DNS response. Returns (rcode, has_answer)."""
    if len(data) < 12:
        return -1, False
    tid, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if tid != expected_tid:
        return -1, False  # Response doesn't match our query
    rcode = flags & 0x0F
    return rcode, ancount > 0


def dns_query(server: str, domain: str, timeout: float = 2.0, qtype: int = 1) -> Optional[float]:
    """Send a DNS query and return latency in ms, or None on failure."""
    packet, tid = build_dns_query(domain, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - start) * 1000
        rcode, has_answer = parse_dns_response(data, tid)
        if rcode == 0:
            return elapsed
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def check_nxdomain(server: str, timeout: float = 2.0) -> bool:
    """Check if server properly returns NXDOMAIN for non-existent domains."""
    fake_domain = f"nxtest-{random.randint(100000,999999)}.definitelynotreal.example"
    packet, tid = build_dns_query(fake_domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        rcode, has_answer = parse_dns_response(data, tid)
        # RCODE 3 = NXDOMAIN (correct), anything else = hijacking
        return rcode == 3
    except (socket.timeout, OSError):
        return True  # Timeout = can't determine, assume OK
    finally:
        sock.close()

# ─── Benchmark Engine ───────────────────────────────────────────────────────────

TEST_DOMAINS = [
    "google.com", "amazon.com", "facebook.com", "cloudflare.com",
    "github.com", "microsoft.com", "apple.com", "netflix.com",
    "reddit.com", "wikipedia.org",
]

@dataclass
class ServerResult:
    name: str
    ip: str
    ip2: Optional[str]
    tags: List[str]
    latencies: List[float] = field(default_factory=list)
    failures: int = 0
    total_queries: int = 0
    nxdomain_ok: bool = True
    avg_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    jitter_ms: float = 0.0
    reliability: float = 0.0
    gaming_score: float = 0.0
    overall_score: float = 0.0


def benchmark_server(name: str, ip: str, ip2: Optional[str], tags: List[str],
                     rounds: int = 10, timeout: float = 2.0) -> ServerResult:
    """Benchmark a single DNS server."""
    result = ServerResult(name=name, ip=ip, ip2=ip2, tags=tags)

    for _ in range(rounds):
        domain = random.choice(TEST_DOMAINS)
        result.total_queries += 1
        latency = dns_query(ip, domain, timeout=timeout)
        if latency is not None:
            result.latencies.append(latency)
        else:
            result.failures += 1

    if result.latencies:
        result.avg_ms = mean(result.latencies)
        result.min_ms = min(result.latencies)
        result.max_ms = max(result.latencies)
        result.jitter_ms = stdev(result.latencies) if len(result.latencies) > 1 else 0.0
    else:
        result.avg_ms = 9999
        result.min_ms = 9999
        result.max_ms = 9999
        result.jitter_ms = 9999

    result.reliability = (1 - result.failures / result.total_queries) * 100 if result.total_queries > 0 else 0
    result.nxdomain_ok = check_nxdomain(ip, timeout=timeout)

    # Gaming score: latency 40%, jitter 30%, reliability 20%, NXDOMAIN 10%
    lat_score = max(0, 100 - result.avg_ms * 1.5)
    jit_score = max(0, 100 - result.jitter_ms * 5)
    rel_score = result.reliability
    nx_score = 100 if result.nxdomain_ok else 0
    result.gaming_score = lat_score * 0.4 + jit_score * 0.3 + rel_score * 0.2 + nx_score * 0.1

    # Overall score: balanced
    result.overall_score = lat_score * 0.3 + jit_score * 0.2 + rel_score * 0.35 + nx_score * 0.15

    return result

# ─── Display ────────────────────────────────────────────────────────────────────

def grade(score: float) -> str:
    if score >= 90: return f"{C.GREEN}{C.BOLD}A+{C.RESET}"
    if score >= 80: return f"{C.GREEN}A{C.RESET}"
    if score >= 70: return f"{C.GREEN}B{C.RESET}"
    if score >= 60: return f"{C.YELLOW}C{C.RESET}"
    if score >= 50: return f"{C.YELLOW}D{C.RESET}"
    return f"{C.RED}F{C.RESET}"


def latency_color(ms: float) -> str:
    if ms < 20: return C.GREEN
    if ms < 50: return C.YELLOW
    return C.RED


def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════╗
║   dns-bench v{__version__}  —  DNS Benchmark & Diagnostic Tool   ║
║   Test 29 DNS servers from YOUR network                  ║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")


def print_results(results: List[ServerResult], sort_key: str = "overall_score",
                  show_tags: Optional[List[str]] = None, top_n: int = 0):
    """Print results as a formatted table."""
    if show_tags:
        results = [r for r in results if any(t in r.tags for t in show_tags)]

    results = sorted(results, key=lambda r: getattr(r, sort_key), reverse=(sort_key.endswith("score")))

    if top_n > 0:
        results = results[:top_n]

    # Header
    print(f" {C.BOLD}{'#':>2}  {'Provider':<22} {'IP':<16} {'Avg':>8} {'Min':>8} {'Jitter':>8} {'Rel':>6} {'NX':>4} {'Score':>6}  Grade{C.RESET}")
    print(f" {'─'*2}  {'─'*22} {'─'*16} {'─'*8} {'─'*8} {'─'*8} {'─'*6} {'─'*4} {'─'*6}  {'─'*5}")

    for i, r in enumerate(results, 1):
        lc = latency_color(r.avg_ms)
        nx_text = "OK" if r.nxdomain_ok else "HJ"
        nx_color = C.GREEN if r.nxdomain_ok else C.RED
        sc = r.gaming_score if sort_key == "gaming_score" else r.overall_score
        g = grade(sc)

        if r.avg_ms >= 9999:
            print(f" {i:>2}  {r.name:<22} {r.ip:<16} {C.RED}{'TIMEOUT':>8}{C.RESET} {'-':>8} {'-':>8} {'-':>6} {nx_color}{nx_text:>4}{C.RESET} {'-':>6}  {C.RED}F{C.RESET}")
        else:
            print(f" {i:>2}  {r.name:<22} {r.ip:<16} {lc}{r.avg_ms:>6.1f}ms{C.RESET} {r.min_ms:>6.1f}ms {r.jitter_ms:>6.1f}ms {r.reliability:>5.0f}% {nx_color}{nx_text:>4}{C.RESET} {sc:>5.0f}  {g}")

    print()


def print_winner(results: List[ServerResult], mode: str):
    """Print the recommended DNS server."""
    if not results:
        return

    key = "gaming_score" if mode == "gaming" else "overall_score"
    winner = max(results, key=lambda r: getattr(r, key))

    if winner.avg_ms >= 9999:
        print(f" {C.RED}No reachable servers found. Check your network connection.{C.RESET}")
        print()
        return

    print(f" {C.BOLD}{C.GREEN}{'═'*58}{C.RESET}")
    if mode == "gaming":
        print(f" {C.BOLD}{C.GREEN} BEST FOR GAMING: {winner.name} ({winner.ip}){C.RESET}")
        print(f"  Latency: {winner.avg_ms:.1f}ms | Jitter: {winner.jitter_ms:.1f}ms | Score: {winner.gaming_score:.0f}")
    else:
        print(f" {C.BOLD}{C.GREEN} RECOMMENDED: {winner.name} ({winner.ip}){C.RESET}")
        print(f"  Latency: {winner.avg_ms:.1f}ms | Reliability: {winner.reliability:.0f}% | Score: {winner.overall_score:.0f}")

    if winner.ip2:
        print(f"  Secondary: {winner.ip2}")
    print(f" {C.BOLD}{C.GREEN}{'═'*58}{C.RESET}")
    print()
    print(f" {C.DIM}Copy these DNS addresses to your network settings.")
    print(f" For setup guides, visit: https://publicdns.info/guides.html{C.RESET}")
    print(f" {C.DIM}Full web benchmark: https://publicdns.info/dns-gaming-benchmark.html{C.RESET}")
    print()


def output_json(results: List[ServerResult]):
    """Output results as JSON."""
    data = {
        "tool": "dns-bench",
        "version": __version__,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [asdict(r) for r in sorted(results, key=lambda r: r.overall_score, reverse=True)],
        "web_benchmark": "https://publicdns.info/dns-gaming-benchmark.html",
    }
    print(json.dumps(data, indent=2))


def output_markdown(results: List[ServerResult]):
    """Output results as shareable markdown."""
    results = sorted(results, key=lambda r: r.overall_score, reverse=True)
    print(f"# DNS Benchmark Results")
    print(f"*Generated by [dns-bench](https://github.com/riankellyjn-a11y/dns-bench) v{__version__}*\n")
    print(f"| # | Provider | IP | Avg (ms) | Jitter (ms) | Reliability | NX | Score |")
    print(f"|---|----------|-----|----------|-------------|-------------|-----|-------|")
    for i, r in enumerate(results[:15], 1):
        nx = "OK" if r.nxdomain_ok else "HIJACK"
        name = r.name.replace('|', '\\|')
        if r.avg_ms >= 9999:
            print(f"| {i} | {name} | `{r.ip}` | TIMEOUT | - | - | - | - |")
        else:
            print(f"| {i} | {name} | `{r.ip}` | {r.avg_ms:.1f} | {r.jitter_ms:.1f} | {r.reliability:.0f}% | {nx} | {r.overall_score:.0f} |")
    print(f"\n*Web version: [publicdns.info/dns-gaming-benchmark.html](https://publicdns.info/dns-gaming-benchmark.html)*")

# ─── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="dns-bench - Fast DNS Benchmark & Diagnostic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Web version: https://publicdns.info/dns-gaming-benchmark.html"
    )
    parser.add_argument("--gaming", action="store_true", help="Gaming mode (prioritize latency + jitter)")
    parser.add_argument("--privacy", action="store_true", help="Test only privacy-focused servers")
    parser.add_argument("--family", action="store_true", help="Test only family-safe servers")
    parser.add_argument("--security", action="store_true", help="Test only security-focused servers")
    parser.add_argument("--fast", action="store_true", help="Quick test (3 rounds instead of 10)")
    parser.add_argument("--rounds", type=int, default=10, help="Number of test rounds (default: 10)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Query timeout in seconds (default: 2.0)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--markdown", action="store_true", help="Output shareable markdown")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--top", type=int, default=0, help="Show only top N results")
    parser.add_argument("--version", action="version", version=f"dns-bench {__version__}")

    args = parser.parse_args()

    if args.no_color or args.json:
        C.disable()

    rounds = 3 if args.fast else args.rounds
    if rounds < 1:
        rounds = 1
    elif rounds > 1000:
        rounds = 1000
    if args.timeout <= 0:
        args.timeout = 2.0
    elif args.timeout > 30:
        args.timeout = 30.0

    filter_tags = []
    if args.privacy: filter_tags = ["privacy"]
    elif args.family: filter_tags = ["family"]
    elif args.security: filter_tags = ["security"]
    elif args.gaming: filter_tags = ["gaming", "fast"]

    servers = DNS_SERVERS
    if filter_tags:
        servers = [s for s in DNS_SERVERS if any(t in s[3] for t in filter_tags)]

    if not args.json and not args.markdown:
        print_banner()
        if filter_tags:
            tag_name = filter_tags[0].title()
            print(f" {C.DIM}Mode: {tag_name} | Servers: {len(servers)} | Rounds: {rounds} | Timeout: {args.timeout}s{C.RESET}")
        else:
            print(f" {C.DIM}Servers: {len(servers)} | Rounds: {rounds} | Timeout: {args.timeout}s{C.RESET}")
        print(f" {C.DIM}Testing from your network...{C.RESET}\n")

    # Run benchmarks in parallel
    results = []
    try:
      with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for name, ip, ip2, tags in servers:
            f = executor.submit(benchmark_server, name, ip, ip2, tags, rounds, args.timeout)
            futures[f] = name

        total = len(futures)
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            try:
                result = future.result()
                results.append(result)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                server_name = futures[future]
                if not args.json and not args.markdown:
                    sys.stderr.write(f"\n Warning: {server_name} benchmark failed: {exc}\n")
            if not args.json and not args.markdown:
                pct = int(done / total * 30)
                if sys.stdout.encoding and sys.stdout.encoding.lower().startswith('utf'):
                    bar = f"{'█' * pct}{'░' * (30 - pct)}"
                else:
                    bar = f"{'#' * pct}{'.' * (30 - pct)}"
                sys.stdout.write(f"\r {C.CYAN}[{bar}] {done}/{total} {futures[future]:<22}{C.RESET}")
                sys.stdout.flush()

      if not args.json and not args.markdown:
        sys.stdout.write("\r" + " " * 80 + "\r")
        print()
    except KeyboardInterrupt:
        if not args.json and not args.markdown:
            sys.stdout.write("\r" + " " * 80 + "\r")
            print(f"\n {C.YELLOW}Benchmark interrupted. Showing partial results...{C.RESET}\n")

    if not results:
        if not args.json:
            print(f" {C.RED}No results collected. Check your network connection.{C.RESET}")
        sys.exit(1)

    # Output
    if args.json:
        output_json(results)
    elif args.markdown:
        output_markdown(results)
    else:
        sort_key = "gaming_score" if args.gaming else "overall_score"
        show_tags = None
        if args.privacy: show_tags = ["privacy"]
        elif args.family: show_tags = ["family"]
        elif args.security: show_tags = ["security"]

        print_results(results, sort_key=sort_key, show_tags=show_tags, top_n=args.top)
        mode = "gaming" if args.gaming else "overall"
        filtered_results = results
        if show_tags:
            filtered_results = [r for r in results if any(t in r.tags for t in show_tags)]
        print_winner(filtered_results or results, mode)

        # Hijack warning
        hijacked = [r for r in results if not r.nxdomain_ok and r.avg_ms < 9999]
        if hijacked:
            print(f" {C.RED}{C.BOLD}WARNING: {len(hijacked)} server(s) hijack NXDOMAIN responses:{C.RESET}")
            for r in hijacked:
                print(f"   {C.RED}• {r.name} ({r.ip}) — redirects failed lookups instead of returning errors{C.RESET}")
            print(f"   {C.DIM}Learn more: https://publicdns.info/guides/nxdomain-hijacking.html{C.RESET}")
            print()


if __name__ == "__main__":
    main()
