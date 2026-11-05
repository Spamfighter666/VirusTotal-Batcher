#!/usr/bin/env python3
"""Resolve current A records using the system's configured DNS resolver."""

import argparse

import dns.exception
import dns.name
import dns.resolver


def main(hostname_to_resolve):
    try:
        answers = dns.resolver.resolve(hostname_to_resolve, "A", lifetime=5, search=False)
        return " ".join(sorted({answer.address for answer in answers}))
    except (dns.exception.DNSException, UnicodeError, ValueError):
        return "Live resolution failed"


def standalone(hostname_to_resolve):
    return dns.name.from_text(hostname_to_resolve), main(hostname_to_resolve)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname")
    print(main(parser.parse_args().hostname))
