"""Interactive and command-line batch lookups against VirusTotal."""

import argparse
import asyncio
import csv
import ipaddress
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import config as cfg
import reno
from vtmgfunctions import HEADERS, VTError, VirusTotal, is_domain, is_ip, is_url


MODES = {"domain": 1, "ip": 2, "url": 3, "submit": 4}
LABELS = {1: "Domain-pDNS", 2: "IP-pDNS", 3: "URL-Lookup", 4: "URL-Submission"}


def user_prompt():
    while True:
        selection = input("Choose a lookup: 1 Domain, 2 IP or CIDR, 3 URL report, 4 Submit URL, 0 Quit: ")
        if selection in {"0", "1", "2", "3", "4"}:
            return int(selection)


def indicators(lines, mode):
    validator = {1: is_domain, 2: is_ip, 3: is_url, 4: is_url}[mode]
    for line in lines:
        value = line.strip()
        if not value:
            continue
        if not validator(value) or (mode == 1 and is_ip(value)):
            yield value, "Invalid input for selected mode (CIDR limit: 65,536 addresses)"
        elif mode == 2:
            for address in ipaddress.ip_network(value, strict=False):
                yield str(address), None
        else:
            yield value, None


def add_live_results(rows, mode, cache):
    for row in rows:
        hostname = row[4] or (row[0] if mode == 1 else "")
        if hostname and hostname not in cache:
            cache[hostname] = reno.main(hostname)
        yield row[:5] + (cache.get(hostname, ""),) + row[6:]


async def dnsloop(hosts, label):
    """Resolve hosts for the bundled dmunge script without blocking its event loop."""
    return [(host, await asyncio.to_thread(reno.main, host)) for host in dict.fromkeys(hosts)]


def run_batch(client, source, output_dir, mode, *, live_dns=False):
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S-%fZ")
    base = output_dir / f"VT-{LABELS[mode]}"
    results = base.with_name(f"{base.name}-Results-{stamp}.csv")
    failures = base.with_name(f"{base.name}-Failures-{stamp}.csv")
    cache = {}
    status = 0
    with (source.open(encoding="utf-8-sig") as lines,
          results.open("x", encoding="utf-8", newline="") as result_file,
          failures.open("x", encoding="utf-8", newline="") as failure_file):
        writer = csv.writer(result_file)
        errors = csv.writer(failure_file)
        writer.writerow(HEADERS[mode])
        errors.writerow(("Query", "Status", "Reason"))
        for value, invalid in indicators(lines, mode):
            if invalid:
                errors.writerow((value, "Invalid", invalid))
                status = 1
                continue
            try:
                rows = client.lookup(value, mode)
            except VTError as error:
                errors.writerow((value, "Not found" if error.missing else "Error", str(error)))
                status = 1
                if error.fatal:
                    print(f"Stopped at {value!r}: {error}. Later inputs were not processed.", file=sys.stderr)
                    break
            else:
                writer.writerows(add_live_results(rows, mode, cache) if live_dns else rows)
            result_file.flush()
            failure_file.flush()
    print(f"Results: {results}\nFailures: {failures}")
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, help="lookup type (omit for the interactive menu)")
    parser.add_argument("--input", type=Path, default=Path(cfg.home_path) / "input/VTlookup.txt")
    parser.add_argument("--output-dir", type=Path, default=Path(cfg.home_path) / "results/virustotal")
    parser.add_argument("--live-dns", action="store_true", help="resolve A records in domain or IP mode")
    parser.add_argument("--related-urls", action="store_true", help="include malicious related URLs (Premium)")
    parser.add_argument("--requests-per-minute", type=int, default=4)
    parser.add_argument("--request-budget", type=int, default=500, help="per-run limit (0 disables the local budget)")
    args = parser.parse_args(argv)
    if args.requests_per_minute < 1 or args.request_budget < 0:
        parser.error("request rate must be positive and request budget must be non-negative")

    interactive = args.mode is None
    try:
        mode = user_prompt() if interactive else MODES[args.mode]
        if not mode:
            return 0
        if not args.input.is_file():
            parser.error(f"input file does not exist: {args.input}")
        key = os.environ.get("VT_API_KEY", "").strip()
        if not key:
            parser.error("set the VT_API_KEY environment variable")
        live_dns = args.live_dns
        if interactive and mode in (1, 2) and not live_dns:
            live_dns = input("Resolve current A records? [y/N] ").strip().lower() == "y"
        if interactive and mode == 4:
            if input("Submit these URLs to VirusTotal for scanning? [y/N] ").strip().lower() != "y":
                return 0
        client = VirusTotal(key, args.requests_per_minute, args.request_budget,
                            related_urls=args.related_urls)
        return run_batch(client, args.input, args.output_dir, mode, live_dns=live_dns and mode in (1, 2))
    except (OSError, UnicodeError, EOFError) as error:
        print(f"Batch could not complete: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. Any rows already written remain in the output directory.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
