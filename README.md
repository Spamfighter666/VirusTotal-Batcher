# VirusTotal Batch Machine Gun

Batch lookups for domains, IP addresses, CIDR ranges and URLs using the
[VirusTotal v3 API](https://docs.virustotal.com/reference/overview). The tool can
also submit URLs for analysis and optionally resolve current DNS A records for
comparison with VirusTotal's historical observations.

Designed by Spamfighter666, coded by Adam. Licensed under [MIT](LICENSE).

## Install

Use Python 3.12, 3.13 or 3.14. In a clone of this repository:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python vtmachinegun.py --help
```

On Windows, activate with `.venv\Scripts\activate` or run the virtual
environment's Python executable directly. Use your [VirusTotal API key](https://docs.virustotal.com/reference/authentication)
as the `VT_API_KEY` environment variable. For example, in Bash you can set it
without putting its value into shell history:

```bash
read -rs -p 'VirusTotal API key: ' VT_API_KEY
echo
export VT_API_KEY
```

The API key is sent in the `x-apikey` request header. Users migrating from
the original version should remove their key from `config.py` and rotate any
key that was previously committed or exposed.

## Run a batch

Place one indicator per line in a UTF-8 text file, using a single input type
per file. The default file is `input/VTlookup.txt`, relative to the repository
root or to `VTMG_HOME` if set. Run `python vtmachinegun.py` for the interactive
menu or specify a mode explicitly:

```sh
python vtmachinegun.py --mode domain --input domains.txt --live-dns
python vtmachinegun.py --mode ip --input addresses.txt
python vtmachinegun.py --mode url --input urls.txt --output-dir results
python vtmachinegun.py --mode submit --input urls-to-scan.txt
```

- **Domain** looks up historical IP resolutions and observed subdomains.
- **IP** looks up ASN and historical hostname resolutions. Both IPv4 and IPv6
  are accepted. Each CIDR expands to at most 65,536 addresses.
- **URL** fetches existing analysis results. The score is the number of
  engines reporting the URL as malicious. A missing score is blank.
- **Submit** requests scanning and records the returned analysis ID. Fetch
  the report later using URL mode. The submission mode retains best-effort
  email redaction. Review indicators for confidential or personal information
  before querying or submitting them to VirusTotal.
- **Live DNS** resolves A records through your configured DNS resolver.
  VirusTotal's pDNS results come from separate historical data.

Each run creates timestamped results and failure CSVs under
`results/virustotal` by default. Timestamps are UTC. IP mode writes all
addresses to a single results file. The failure CSV distinguishes invalid
inputs, absent reports and API errors. Exit status 1 indicates failed inputs
or an interrupted batch due to an API error or quota. A fatal API error stops
at the affected input and preserves completed rows. A relationship lookup
that fails partway is reported as a failure for that indicator.

## Quotas and Premium access

VirusTotal documents a [Public API limit](https://docs.virustotal.com/reference/public-vs-premium-api)
of four requests per minute and 500 per day, along with restrictions on
commercial and business use. Requests are paced sequentially at four per
minute by default, with a 500-request cap per run. Report requests, relationship
pages and retries all count. VirusTotal enforces the actual quota across runs
and applications sharing a key. For licensed Premium use, set
`--requests-per-minute` and `--request-budget` to suit your plan. A budget of 0
removes the local cap.

The v3 domain and IP related-URL endpoints require Premium access. Use
`--related-urls` with a key that has those permissions to include malicious
related URLs. Standard passive DNS queries and subdomain queries do not
require that flag. Requests retry transient read failures and short rate limits
with a bounded delay. An ambiguous submission failure is recorded for review
because replaying a submission could create a duplicate.

## Bundled domain reduction script

This repository also includes `dmunge.py`. It reduces hostnames and URLs
to registrable domains using the Public Suffix List snapshot bundled with
`tldextract`. Put input in `input/dmunge.txt` and create
`support/white.txt` (one excluded domain per line) and `support/splist.csv`
(one `suffix,abuse_contact` pair per row). The two support files may be empty.
To filter popular domains, supply your own optional `support/top-1m.csv` in
`rank,domain` format. Run `python dmunge.py` and find output under
`results/dMunge`. This script does not need a VirusTotal key.

## Development

```sh
python -m pip check
python -W error -m compileall -q *.py
python -m unittest discover -s tests -v
```

The tests use simulated VirusTotal and DNS responses. For a live smoke test,
use an authorized key and a small input of public indicators. Use a Premium
key to verify `--related-urls` and explicitly select submit mode to test scanning.
