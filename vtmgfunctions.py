"""VirusTotal v3 requests and the batcher's CSV row formats."""

import base64
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


API_ROOT = "https://www.virustotal.com/api/v3"
HEADERS = {
    1: ("Query", "Last pDNS", "pDNS Time", "pDNS IP", "Observed Subdomains",
        "Live Resolution", "Scan Date", "Scan Time", "Score", "URL"),
    2: ("Query", "ASN", "Last pDNS", "pDNS Time", "Hostname",
        "Live Resolution", "Scan Date", "Scan Time", "Score", "URL"),
    3: ("Scan Date", "Score", "URL"),
    4: ("Query", "Scan Date", "Status"),
}


class VTError(Exception):
    def __init__(self, message, *, fatal=False, missing=False):
        super().__init__(message)
        self.fatal = fatal
        self.missing = missing


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def retry_delay(value, fallback):
    try:
        return max(0, int(value))
    except (ValueError, TypeError):
        if value:
            try:
                return max(0, parsedate_to_datetime(value).timestamp() - time.time())
            except (ValueError, TypeError, OverflowError):
                pass
        return fallback


class VirusTotal:
    def __init__(self, key, requests_per_minute=4, daily_limit=500, *, related_urls=False):
        self.key = key
        self.interval = 60 / requests_per_minute
        self.daily_limit = daily_limit
        self.related_urls = related_urls
        self.requests = 0
        self.next_request = 0
        self.opener = build_opener(NoRedirect())

    def request(self, path, *, form=None):
        url = path if path.startswith("https://") else API_ROOT + path
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc) != ("https", "www.virustotal.com") or not parts.path.startswith("/api/v3/"):
            raise VTError("VirusTotal returned an invalid pagination URL")
        data = urlencode(form).encode("ascii") if form is not None else None
        req = Request(url, data, {"x-apikey": self.key, "Accept": "application/json"})
        for attempt in range(3):
            if self.daily_limit and self.requests >= self.daily_limit:
                raise VTError("Configured per-run request budget reached", fatal=True)
            delay = self.next_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.next_request = time.monotonic() + self.interval
            self.requests += 1
            try:
                with self.opener.open(req, timeout=30) as response:
                    payload = json.load(response)
                if not isinstance(payload, dict) or "data" not in payload:
                    raise VTError("VirusTotal returned an invalid response")
                return payload
            except HTTPError as error:
                status = error.code
                wait = retry_delay(error.headers.get("Retry-After"), 2 ** attempt)
                with error:
                    try:
                        code = json.load(error)["error"]["code"]
                    except (ValueError, KeyError, TypeError):
                        code = None
                if status == 401:
                    raise VTError("VirusTotal rejected the API key (HTTP 401)", fatal=True) from None
                if status == 429 and ((code == "QuotaExceededError" and not error.headers.get("Retry-After")) or wait > 60):
                    raise VTError("VirusTotal quota or extended rate limit reached (HTTP 429)", fatal=True) from None
                # A rejected 429 can be retried, but an ambiguous POST failure could duplicate a submission.
                retryable = status == 429 or (data is None and status in {500, 502, 503, 504})
                if not retryable or attempt == 2:
                    if status == 403:
                        message = "VirusTotal denied access (HTTP 403); check key permissions and plan"
                    else:
                        message = f"VirusTotal returned HTTP {status}"
                    raise VTError(message, missing=status == 404, fatal=status == 429) from None
                self.next_request = max(self.next_request, time.monotonic() + min(wait, 60))
            except (URLError, TimeoutError, OSError):
                if data is not None or attempt == 2:
                    raise VTError("VirusTotal request failed at the network layer") from None
                self.next_request = max(self.next_request, time.monotonic() + 2 ** attempt)
            except ValueError:
                raise VTError("VirusTotal returned invalid JSON") from None

    def relationship(self, path):
        seen = set()
        while path:
            if path in seen:
                raise VTError("VirusTotal repeated a pagination link")
            seen.add(path)
            payload = self.request(path)
            if not isinstance(payload["data"], list):
                raise VTError("VirusTotal returned an invalid relationship")
            yield from payload["data"]
            path = payload.get("links", {}).get("next")

    def lookup(self, value, mode):
        try:
            return self._lookup(value, mode)
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError, OSError):
            raise VTError("VirusTotal returned malformed report data") from None

    def _lookup(self, value, mode):
        if mode == 3:
            identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            item = self.request(f"/urls/{identifier}")["data"]
            date, clock, score, url = url_fields(item, value)
            return [(" ".join(filter(None, (date, clock))), score, url)]
        if mode == 4:
            redacted = burn_with_fire(value)
            item = self.request("/urls", form={"url": redacted})["data"]
            return [(redacted, "", f"Submitted (analysis ID: {item['id']})")]

        domain = mode == 1
        endpoint = "domains" if domain else "ip_addresses"
        identifier = value.rstrip(".").encode("idna").decode() if domain else value
        path = f"/{endpoint}/{quote(identifier, safe=':')}"
        report = self.request(path)["data"].get("attributes", {})
        asn = report.get("asn", "")
        rows = []
        for item in self.relationship(path + "/resolutions"):
            attr = item.get("attributes", {})
            date, clock = timestamp_parts(attr.get("date"))
            if domain:
                row = (value, date, clock, attr.get("ip_address", ""), "", "")
            else:
                row = (value, asn, date, clock, attr.get("host_name", ""), "")
            rows.append(row + ("", "", "", ""))
        if domain:
            for item in self.relationship(path + "/subdomains"):
                rows.append((value, "", "", "", item["id"], "", "", "", "", ""))
        if self.related_urls:
            for item in self.relationship(path + "/urls"):
                fields = url_fields(item)
                if fields[2]:
                    prefix = (value, "", "", "", "", "") if domain else (value, asn, "", "", "", "")
                    rows.append(prefix + fields)
        if not rows:
            prefix = (value, "", "", "", "", "") if domain else (value, asn, "", "", "", "")
            rows.append(prefix + ("", "", "", ""))
        return rows


def timestamp_parts(seconds):
    if seconds is None:
        return "", ""
    date = datetime.fromtimestamp(seconds, timezone.utc)
    return date.strftime("%Y-%m-%d"), date.strftime("%H:%M:%S")


def url_fields(item, fallback=""):
    attr = item.get("attributes", {})
    date, clock = timestamp_parts(attr.get("last_analysis_date"))
    score = attr.get("last_analysis_stats", {}).get("malicious", "")
    return date, clock, score, attr.get("url", fallback)


def is_ip(value):
    try:
        return ipaddress.ip_network(value, strict=False).num_addresses <= 65536
    except ValueError:
        return False


def is_url(value):
    try:
        parts = urlsplit(value)
        return (parts.scheme in {"http", "https"} and bool(parts.hostname)
                and parts.username is None and not any(char.isspace() for char in value))
    except ValueError:
        return False


def is_domain(value):
    try:
        ascii_value = value.rstrip(".").encode("idna").decode()
    except UnicodeError:
        return False
    return len(ascii_value) <= 253 and all(
        re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)", label)
        for label in ascii_value.split(".")
    )


def burn_with_fire(url):
    """Retain the original tool's email redaction for explicit submissions."""
    return re.sub(r"[\w.!$%'*+^_`{|}~-]+(?:@|%40)[\w.-]+\.[A-Za-z]{2,}",
                  "email@example.com", url, flags=re.IGNORECASE)
