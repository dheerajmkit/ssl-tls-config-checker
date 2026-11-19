#!/usr/bin/env python3
"""Audit SSL/TLS configurations from an inventory or live.

Usage:
    python3 run.py <hosts.json> [--json]
    python3 run.py --live <host[:port]> [--json]

Exit codes: 2 = usage error / unreadable inventory / live check failed,
            1 = at least one high or critical finding,
            0 = no high or critical findings.
"""

import argparse
import sys

from tls.checker import load_hosts, check_host, live_check
from tls.checks import check_hosts
from tls.report import summarize, render_text, render_json


def _parse_live(value):
    if ":" in value:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, 443


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", nargs="?",
                        help="host inventory JSON file")
    parser.add_argument("--live", help="live host, optionally host:port")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    args = parser.parse_args(argv)

    if args.live:
        try:
            host, port = _parse_live(args.live)
            hosts = [live_check(host, port)]
        except (OSError, ValueError) as exc:
            print(f"error: live check failed: {exc}", file=sys.stderr)
            return 2
        source = f"live:{args.live}"
    elif args.inventory:
        try:
            hosts = load_hosts(args.inventory)
        except (OSError, ValueError) as exc:
            print(f"error: cannot load inventory: {exc}", file=sys.stderr)
            return 2
        source = args.inventory
    else:
        parser.print_usage(sys.stderr)
        print("error: provide an inventory file or --live", file=sys.stderr)
        return 2

    findings = check_hosts(hosts)

    if args.json:
        print(render_json(source, findings))
    else:
        print(render_text(source, findings))

    counts = summarize(findings)
    return 1 if (counts["CRITICAL"] or counts["HIGH"]) else 0


if __name__ == "__main__":
    sys.exit(main())
