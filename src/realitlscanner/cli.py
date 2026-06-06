from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import re
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")

from realitlscanner.geo import Geo

logger = logging.getLogger(__name__)

SCAN_CSV_HEADER = ["IP", "ORIGIN", "TLS", "ALPN", "CERT_LENGTH", "CERT_SIGNATURE", "CERT_PUBLICKEY", "CERT_DOMAIN", "CERT_ISSUER", "GEO_CODE"]

EXCLUDE_DOMAIN_PATTERNS = [
    "localhost", "server.domain.com", "*",
    "kubernetes ingress", "cloudflare origin certificate",
    "fortigate", "unspecified",
]


def _should_exclude_domain(domain: str) -> bool:
    if not domain or len(domain) < 3:
        return True
    domain_lower = domain.lower()
    return any(p in domain_lower for p in EXCLUDE_DOMAIN_PATTERNS)


def _print_check_results(results, *, verbose: bool = False) -> None:
    from realitlscanner.models import CheckResult

    suitable = [r for r in results if r.suitable]
    unsuitable = [r for r in results if not r.suitable]

    print(f"\n{'='*80}")
    print(f"  检测完成: {len(results)} 个域名, {len(suitable)} 个适合, {len(unsuitable)} 个不适合")
    print(f"{'='*80}\n")

    if suitable:
        print("✓ 适合作为 Reality dest 的域名:\n")
        print(f"  {'域名':<35} {'TLS1.3':>6} {'X25519':>7} {'H2':>3} {'SNI':>4} {'CDN':<4} {'热门':<4} {'证书有效期'}")
        print(f"  {'-'*35} {'-'*6} {'-'*7} {'-'*3} {'-'*4} {'-'*4} {'-'*4} {'-'*10}")
        for r in suitable:
            cdn_mark = r.cdn_confidence if r.is_cdn else "-"
            hot_mark = "是" if r.is_hot_website else "-"
            print(f"  {r.final_domain or r.domain:<35} {'✓':>6} {'✓':>7} {'✓':>3} {'✓':>4} {cdn_mark:<4} {hot_mark:<4} {r.cert_days_left}天")
        print()

    if unsuitable and verbose:
        print("✗ 不适合的域名:\n")
        for r in unsuitable:
            print(f"  {r.domain:<35} → {r.error}")
        print()


# ─── find: scan + check in one pass ────────────────────────────────────────────


async def _run_find(args: argparse.Namespace) -> None:
    from realitlscanner.checker import check_domain
    from realitlscanner.models import CheckResult, Host
    from realitlscanner.scanner import scan_tls
    from realitlscanner.utils import iterate_addr, iterate_lines

    import httpx

    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text

    geo = Geo()
    check_results: list[CheckResult] = []
    seen_domains: set[str] = set()
    suitable_count = 0
    target_count = args.num

    stop_event = asyncio.Event()
    scanned_count = 0
    feasible_count = 0

    console = Console()
    from rich.box import SIMPLE_HEAD

    table = Table(
        title=f"Reality Finder — finding {target_count} suitable dests",
        title_style="bold",
        box=SIMPLE_HEAD,
        pad_edge=False,
        show_edge=False,
    )
    table.add_column("Rating", justify="center", width=6, no_wrap=True)
    table.add_column("Domain", min_width=24)
    table.add_column("Handshake", justify="right", width=9)
    table.add_column("Validity", justify="right", width=8)
    table.add_column("CDN", justify="center", width=4)
    table.add_column("Hot", justify="center", width=4)

    def _make_display():
        from rich.console import Group
        elapsed = time.time() - t0
        status = Text(f"  {scanned_count} scanned · {feasible_count} feasible · {suitable_count}/{target_count} found · {elapsed:.0f}s", style="dim")
        return Group(table, Text(""), status)

    def _score(result) -> tuple[str, str]:
        if result.is_hot_website:
            return "★", "red"
        if result.is_cdn and result.cdn_confidence in ("高", "中"):
            return "★★", "yellow"
        return "★★★", "green"

    async def scan_worker(host: Host) -> None:
        nonlocal scanned_count, feasible_count
        if stop_event.is_set():
            return
        result = await scan_tls(
            host, port=args.port, timeout_sec=args.timeout,
            geo=geo, enable_ipv6=args.ipv6,
        )
        scanned_count += 1
        if result and result.feasible and not stop_event.is_set():
            domain = result.domain
            if not _should_exclude_domain(domain) and domain not in seen_domains:
                seen_domains.add(domain)
                feasible_count += 1
                await run_check(domain)

    async def run_check(domain: str) -> None:
        nonlocal suitable_count
        if stop_event.is_set():
            return
        result = await check_domain(domain, geo=geo, timeout_sec=args.timeout)
        check_results.append(result)
        if result.suitable and suitable_count < target_count:
            suitable_count += 1
            score_text, score_style = _score(result)
            cdn = result.cdn_confidence if result.is_cdn else "-"
            hot = "Yes" if result.is_hot_website else "-"
            ms = f"{result.handshake_ms:.0f}ms"
            days = f"{result.cert_days_left}d"
            name = result.final_domain or result.domain
            table.add_row(
                Text(score_text, style=score_style),
                name,
                ms,
                days,
                cdn,
                Text(hot, style="red" if hot == "Yes" else "dim"),
            )
            if suitable_count >= target_count:
                stop_event.set()

    t0 = time.time()
    sem = asyncio.Semaphore(args.thread)
    tasks: list[asyncio.Task] = []

    async def throttled_scan(host: Host) -> None:
        async with sem:
            await scan_worker(host)

    async def _refresh_loop(live: Live) -> None:
        while not stop_event.is_set():
            live.update(_make_display())
            await asyncio.sleep(0.15)

    with Live(_make_display(), console=console, refresh_per_second=8) as live:
        refresh_task = asyncio.create_task(_refresh_loop(live))

        if args.addr:
            async for host in iterate_addr(args.addr, count=65536, enable_ipv6=args.ipv6):
                if stop_event.is_set():
                    break
                tasks.append(asyncio.create_task(throttled_scan(host)))
        elif args.input:
            lines = Path(args.input).read_text().splitlines()
            async for host in iterate_lines(lines, enable_ipv6=args.ipv6):
                if stop_event.is_set():
                    break
                tasks.append(asyncio.create_task(throttled_scan(host)))
        elif args.url:
            async with httpx.AsyncClient() as client:
                resp = await client.get(args.url)
                resp.raise_for_status()
                body = resp.text
            domains = list(dict.fromkeys(
                m.group(2) for m in re.finditer(r"(https?)://(.*?)[/\"<>\s]+", body)
            ))
            async for host in iterate_lines(domains, enable_ipv6=args.ipv6):
                if stop_event.is_set():
                    break
                tasks.append(asyncio.create_task(throttled_scan(host)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        stop_event.set()
        refresh_task.cancel()
        try:
            await refresh_task
        except asyncio.CancelledError:
            pass
        live.update(table)

    elapsed = time.time() - t0

    # Final summary
    console.print()
    if suitable_count > 0:
        console.print(f"  [dim]{scanned_count} scanned · {feasible_count} feasible · {suitable_count} passed · {elapsed:.1f}s[/dim]")
        console.print()
        console.print("  [green]★★★[/green] Recommended  [yellow]★★[/yellow] Usable (CDN)  [red]★[/red] Caution (popular site)")
    else:
        console.print(f"  [dim]{scanned_count} scanned · {feasible_count} feasible · 0 passed · {elapsed:.1f}s[/dim]")
        console.print()
        console.print("  [yellow]No suitable domains found. Try a different IP range or increase -thread.[/yellow]")
    console.print()

    if args.verbose:
        unsuitable = [r for r in check_results if not r.suitable]
        if unsuitable:
            console.print("  [dim]Failed:[/dim]")
            for r in unsuitable:
                console.print(f"    [red]✗[/red] {r.domain:<30} [dim]{r.error}[/dim]")
            console.print()

    if args.out and suitable:
        with open(args.out, "w", encoding="utf-8") as f:
            for r in suitable:
                f.write(f"{r.ip_address},{r.final_domain or r.domain}\n")
        print(f"  → 已保存到 {args.out}")
        print()

    geo.close()


# ─── scan: raw TLS scan only ───────────────────────────────────────────────────


async def _run_scan(args: argparse.Namespace) -> None:
    from realitlscanner.models import Host
    from realitlscanner.scanner import scan_tls
    from realitlscanner.utils import iterate_addr, iterate_lines

    import httpx

    geo = Geo()
    out_file = None
    if args.out:
        out_file = open(args.out, "w", encoding="utf-8")
        out_file.write(",".join(SCAN_CSV_HEADER) + "\n")

    queue: asyncio.Queue[Host | None] = asyncio.Queue(maxsize=args.thread * 4)
    results_written = 0

    async def worker() -> None:
        nonlocal results_written
        while True:
            host = await queue.get()
            if host is None:
                queue.task_done()
                break
            try:
                result = await scan_tls(
                    host, port=args.port, timeout_sec=args.timeout,
                    geo=geo, enable_ipv6=args.ipv6,
                )
                if result and result.feasible and out_file:
                    out_file.write(result.to_csv_line() + "\n")
                    out_file.flush()
                    results_written += 1
            finally:
                queue.task_done()

    t0 = time.time()
    workers = [asyncio.create_task(worker()) for _ in range(args.thread)]

    if args.addr:
        logger.info("Started scanning")
        async for host in iterate_addr(args.addr, count=65536, enable_ipv6=args.ipv6):
            await queue.put(host)
    elif args.input:
        lines = Path(args.input).read_text().splitlines()
        logger.info("Started scanning, targets=%d", len(lines))
        async for host in iterate_lines(lines, enable_ipv6=args.ipv6):
            await queue.put(host)
    elif args.url:
        logger.info("Fetching url: %s", args.url)
        async with httpx.AsyncClient() as client:
            resp = await client.get(args.url)
            resp.raise_for_status()
            body = resp.text
        domains = list(dict.fromkeys(
            m.group(2) for m in re.finditer(r"(https?)://(.*?)[/\"<>\s]+", body)
        ))
        logger.info("Parsed domains count=%d", len(domains))
        async for host in iterate_lines(domains, enable_ipv6=args.ipv6):
            await queue.put(host)

    for _ in workers:
        await queue.put(None)
    await asyncio.gather(*workers)

    elapsed = time.time() - t0
    logger.info("Scanning completed, elapsed=%.2fs results=%d", elapsed, results_written)

    if out_file:
        out_file.close()
    geo.close()


# ─── check: verify domains only ───────────────────────────────────────────────


async def _run_check(args: argparse.Namespace) -> None:
    from realitlscanner.checker import check_domain

    geo = Geo()
    domains: list[str] = []

    if args.domain:
        domains = [args.domain]
    elif args.csv_file:
        domains = _extract_domains_from_csv(args.csv_file)
    elif args.file:
        domains = [
            line.strip() for line in Path(args.file).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    if not domains:
        logger.error("No domains to check")
        return

    logger.info("Checking %d domain(s)...", len(domains))
    sem = asyncio.Semaphore(args.thread)
    results = []

    async def worker(domain: str) -> None:
        async with sem:
            result = await check_domain(domain, geo=geo, timeout_sec=args.timeout)
            results.append(result)

    tasks = [asyncio.create_task(worker(d)) for d in domains]
    await asyncio.gather(*tasks)

    _print_check_results(results, verbose=args.verbose)
    geo.close()


def _extract_domains_from_csv(csv_file: str) -> list[str]:
    """Extract domains from a scan CSV output file."""
    domains: list[str] = []
    seen: set[str] = set()

    with open(csv_file, encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return domains

        domain_idx = None
        for i, col in enumerate(header):
            if "CERT_DOMAIN" in col.upper() or "DOMAIN" in col.upper():
                domain_idx = i
                break
        if domain_idx is None:
            domain_idx = min(len(header) - 1, 7)

        for row in reader:
            if len(row) <= domain_idx:
                continue
            domain = row[domain_idx].strip().strip('"')
            if _should_exclude_domain(domain):
                continue
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)

    return domains


# ─── CLI entry point ───────────────────────────────────────────────────────────


def _add_scan_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-addr", help="IP, IP CIDR, or domain to scan")
    group.add_argument("-in", dest="input", help="File with targets (one per line)")
    group.add_argument("-url", help="URL to crawl for domains")
    parser.add_argument("-port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("-thread", type=int, default=10, help="Concurrent tasks (default: 10)")
    parser.add_argument("-timeout", type=int, default=10, help="Timeout per operation in seconds")
    parser.add_argument("-46", dest="ipv6", action="store_true", help="Enable IPv6")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="reality-finder",
        description="Reality protocol dest finder - scan IP ranges and verify domain suitability",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    subparsers = parser.add_subparsers(dest="command")

    # find: the main command (scan + check combined)
    find_parser = subparsers.add_parser("find", help="Scan and verify in one pass (recommended)")
    _add_scan_args(find_parser)
    find_parser.add_argument("-n", "--num", type=int, default=10, help="Stop after finding N suitable domains (default: 10)")
    find_parser.add_argument("-out", default="", help="Save suitable domains to file")

    # scan: raw scan only
    scan_parser = subparsers.add_parser("scan", help="Scan IP ranges (no verification)")
    _add_scan_args(scan_parser)
    scan_parser.add_argument("-out", default="out.csv", help="Output CSV file (default: out.csv)")

    # check: verify only
    check_parser = subparsers.add_parser("check", help="Verify domains for Reality suitability")
    check_group = check_parser.add_mutually_exclusive_group(required=True)
    check_group.add_argument("-d", "--domain", help="Single domain to check")
    check_group.add_argument("-csv", dest="csv_file", help="CSV file from scan output")
    check_group.add_argument("-f", "--file", help="File with domains (one per line)")
    check_parser.add_argument("-thread", type=int, default=5, help="Concurrent checks (default: 5)")
    check_parser.add_argument("-timeout", type=float, default=10.0, help="Timeout per check in seconds")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")
    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    if args.command == "find":
        asyncio.run(_run_find(args))
    elif args.command == "scan":
        asyncio.run(_run_scan(args))
    elif args.command == "check":
        asyncio.run(_run_check(args))


if __name__ == "__main__":
    main()
