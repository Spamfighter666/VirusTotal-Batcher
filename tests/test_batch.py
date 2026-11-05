import base64
import csv
import io
import json
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs

import config
import dmunge
import reno
import vtmachinegun
from vtmgfunctions import API_ROOT, VTError, VirusTotal


def response(data, **extra):
    return io.BytesIO(json.dumps(dict(data=data, **extra)).encode())


def http_error(status, code, retry_after=None):
    headers = Message()
    if retry_after:
        headers["Retry-After"] = retry_after
    return HTTPError(API_ROOT, status, "", headers, response(None, error={"code": code}))


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.client = VirusTotal("test-only-key", requests_per_minute=60)
        clock = patch("vtmgfunctions.time.monotonic", return_value=100)
        self.addCleanup(clock.stop)
        clock.start()
        sleeper = patch("vtmgfunctions.time.sleep")
        self.addCleanup(sleeper.stop)
        self.sleep = sleeper.start()

    def test_url_lookup_encodes_full_url_and_uses_header(self):
        url = "https://example.com/a?one=1,two=2"
        with patch.object(self.client.opener, "open", return_value=response({"attributes": {
            "last_analysis_date": 0, "last_analysis_stats": {"malicious": 2}, "url": url,
        }})) as open_request:
            self.assertEqual(self.client.lookup(url, 3), [("1970-01-01 00:00:00", 2, url)])
        request = open_request.call_args.args[0]
        token = request.full_url.split("/")[-1]
        self.assertEqual(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode(), url)
        self.assertEqual(request.get_header("X-apikey"), "test-only-key")
        self.assertNotIn("test-only-key", request.full_url)

    def test_domain_pagination_and_subdomain_rows(self):
        with patch.object(self.client.opener, "open", side_effect=[
            response({"attributes": {}}),
            response([{"attributes": {"date": 0, "ip_address": "192.0.2.1"}}],
                     links={"next": API_ROOT + "/domains/example.com/resolutions?cursor=page2"}),
            response([{"attributes": {"date": 1, "ip_address": "192.0.2.2"}}]),
            response([{"id": "www.example.com"}]),
        ]) as open_request:
            rows = self.client.lookup("example.com", 1)
        self.assertEqual([row[3] for row in rows[:2]], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(rows[2][4], "www.example.com")
        self.assertIn("cursor=page2", open_request.call_args_list[2].args[0].full_url)
        self.assertEqual(open_request.call_count, 4)

    def test_ip_asn_and_passive_dns(self):
        with patch.object(self.client.opener, "open", side_effect=[
            response({"attributes": {"asn": 64496}}),
            response([{"attributes": {"date": 0, "host_name": "example.com"}}]),
        ]):
            self.assertEqual(self.client.lookup("192.0.2.1", 2)[0][:5],
                             ("192.0.2.1", 64496, "1970-01-01", "00:00:00", "example.com"))

    def test_submission_and_email_redaction(self):
        with patch.object(self.client.opener, "open", return_value=response({"id": "analysis-1"})) as request:
            row, = self.client.lookup("https://example.com/lookup?email=alice%40example.org", 4)
        self.assertIn("analysis-1", row[2])
        sent = request.call_args.args[0]
        self.assertEqual(sent.get_method(), "POST")
        self.assertEqual(parse_qs(sent.data.decode())["url"],
                         ["https://example.com/lookup?email=email@example.com"])

    def test_post_is_not_replayed_after_network_failure(self):
        with patch.object(self.client.opener, "open", side_effect=URLError("timeout")) as request:
            with self.assertRaisesRegex(VTError, "network"):
                self.client.lookup("https://example.com/", 4)
        self.assertEqual(request.call_count, 1)

    def test_retry_after_and_request_budget(self):
        self.client.daily_limit = 2
        with patch.object(self.client.opener, "open", side_effect=[
            http_error(429, "TooManyRequestsError", "9"), response({"attributes": {}}),
        ]) as request:
            self.client.lookup("https://example.com", 3)
            self.assertEqual(request.call_count, 2)
            self.sleep.assert_any_call(9)
            with self.assertRaisesRegex(VTError, "budget"):
                self.client.lookup("https://example.net", 3)

    def test_pagination_cannot_forward_key(self):
        with patch.object(self.client.opener, "open", return_value=response(
                [], links={"next": "https://other.example/api/v3/page"})) as request:
            with self.assertRaisesRegex(VTError, "invalid pagination"):
                list(self.client.relationship("/domains/example.com/resolutions"))
        self.assertEqual(request.call_count, 1)

    def test_cli_writes_quoted_csv_and_distinguishes_missing_results(self):
        url = "https://example.com/a?one=1,two=2"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "urls.txt"
            source.write_text(f"{url}\nhttps://example.net/\n", encoding="utf-8")
            with patch.dict(os.environ, VT_API_KEY="test-only-key"), patch(
                    "vtmachinegun.VirusTotal", return_value=self.client), patch.object(
                    self.client.opener, "open", side_effect=[
                        response({"attributes": {"last_analysis_stats": {"malicious": 1}}}),
                        http_error(404, "NotFoundError"),
                    ]):
                status = vtmachinegun.main(["--mode", "url", "--input", str(source),
                                           "--output-dir", str(directory)])
            self.assertEqual(status, 1)
            with next(directory.glob("*-Results-*.csv")).open(newline="") as output:
                self.assertEqual(list(csv.DictReader(output))[0]["URL"], url)
            with next(directory.glob("*-Failures-*.csv")).open(newline="") as output:
                self.assertEqual(list(csv.DictReader(output))[0]["Status"], "Not found")

    def test_cidr_streams_and_oversized_ranges_are_rejected(self):
        items = list(vtmachinegun.indicators(["192.0.2.1/30", "::/64"], 2))
        self.assertEqual(items[:4], [(f"192.0.2.{i}", None) for i in range(4)])
        self.assertIsNotNone(items[4][1])

    def test_dns_reads_a_records_after_resolution(self):
        from types import SimpleNamespace
        with patch("reno.dns.resolver.resolve", return_value=[
            SimpleNamespace(address="192.0.2.1"), SimpleNamespace(address="192.0.2.1"),
        ]) as resolve:
            self.assertEqual(reno.main("alias.example"), "192.0.2.1")
        resolve.assert_called_once_with("alias.example", "A", lifetime=5, search=False)

    def test_bundled_domain_munger_works_without_alexa_download(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(config, "home_path", temporary):
            directory = Path(temporary)
            support = directory / "support"
            support.mkdir()
            (support / "white.txt").write_text("example.net\n", encoding="utf-8")
            (support / "splist.csv").write_text("", encoding="utf-8")
            source = directory / "domains.txt"
            source.write_text("https://sub.example.com/path sub.example.net", encoding="utf-8")
            domains, failures = dmunge.api(source)
        self.assertEqual(domains, [("example.com", "~none")])
        self.assertEqual(failures, [("sub.example.net", "Whitelist")])


if __name__ == "__main__":
    unittest.main()
