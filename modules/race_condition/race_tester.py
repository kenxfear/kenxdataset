"""
Race Condition Tester Module for Deep Eye.

Tests for TOCTOU and state-based race conditions via concurrent requests.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class RaceConditionTester:
    """Tests for race condition vulnerabilities using concurrent request flooding."""

    DEFAULT_CONCURRENCY = 10
    STATE_CHANGING_METHODS = ["POST", "PUT", "DELETE", "PATCH"]

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.concurrency = config.get("advanced", {}).get("race_concurrency", self.DEFAULT_CONCURRENCY)
        self.timeout = config.get("scanner", {}).get("timeout", 10)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Scan a URL for race condition vulnerabilities.

        Args:
            url: Target URL to test.
            context: Optional context with method, body, headers info.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []
        context = context or {}

        logger.info(f"[RaceCondition] Testing: {url}")

        method = context.get("method", "POST").upper()
        body = context.get("body", {})
        headers = context.get("headers", {})

        # Only test state-changing endpoints
        if method not in self.STATE_CHANGING_METHODS:
            # Try GET-based race condition (e.g., coupon redemption via GET)
            vulns = self._test_get_race(url)
            vulnerabilities.extend(vulns)
        else:
            # Test POST/PUT/DELETE race conditions
            vulns = self._test_state_change_race(url, method, body, headers)
            vulnerabilities.extend(vulns)

        logger.info(f"[RaceCondition] Found {len(vulnerabilities)} potential issues on {url}")
        return vulnerabilities

    def _test_state_change_race(
        self, url: str, method: str, body: Dict, headers: Dict
    ) -> List[Dict]:
        """Send concurrent state-changing requests and look for inconsistencies."""
        vulnerabilities = []

        responses = self._send_concurrent_requests(url, method, body, headers)
        if not responses:
            return vulnerabilities

        analysis = self._analyze_responses(responses)
        if analysis and 'corruption' in analysis.lower():
            vulnerabilities.append({
                "type": "race_condition",
                "severity": "info",
                "url": url,
                "parameter": f"{method} request body",
                "payload": f"{self.concurrency} concurrent {method} requests",
                "evidence": analysis + (
                    ". NOTE: Race condition detection from HTTP response analysis alone is "
                    "inherently unreliable. This finding should be verified through manual testing."
                ),
                "description": (
                    "Potential race condition detected on state-changing endpoint. "
                    "Concurrent requests produced results consistent with possible state corruption. "
                    "HTTP-based race detection is unreliable and this finding requires manual verification."
                ),
                "remediation": (
                    "Implement proper locking mechanisms (database-level locks, optimistic locking, "
                    "or distributed locks). Use idempotency keys for financial operations. "
                    "Apply database transactions with appropriate isolation levels."
                ),
            })

        return vulnerabilities

    def _test_get_race(self, url: str) -> List[Dict]:
        """Test GET-based race conditions (e.g., reading state during modification)."""
        vulnerabilities = []

        responses = self._send_concurrent_requests(url, "GET", None, {})
        if not responses:
            return vulnerabilities

        analysis = self._analyze_responses(responses)
        if analysis and 'corruption' in analysis.lower():
            vulnerabilities.append({
                "type": "race_condition",
                "severity": "info",
                "url": url,
                "parameter": "GET request",
                "payload": f"{self.concurrency} concurrent GET requests",
                "evidence": analysis + (
                    ". NOTE: Race condition detection from HTTP response analysis alone is "
                    "inherently unreliable. This finding should be verified through manual testing."
                ),
                "description": (
                    "Potential race condition on read endpoint. Concurrent requests produced "
                    "results consistent with possible state corruption. "
                    "HTTP-based race detection is unreliable and this finding requires manual verification."
                ),
                "remediation": (
                    "Ensure read operations are atomic. Use database transactions with "
                    "appropriate isolation levels. Implement caching with proper invalidation."
                ),
            })

        return vulnerabilities

    def _send_concurrent_requests(
        self, url: str, method: str, body: Optional[Dict], headers: Dict
    ) -> List[Dict]:
        """Send N concurrent requests and collect responses."""
        results = []

        def make_request(request_id: int) -> Optional[Dict]:
            try:
                start = time.time()
                if method == "GET":
                    response = self.http_client.get(url, timeout=self.timeout)
                elif method == "POST":
                    response = self.http_client.post(
                        url, json=body, headers=headers, timeout=self.timeout
                    )
                elif method == "PUT":
                    response = self.http_client.post(
                        url, json=body, headers=headers, timeout=self.timeout
                    )
                else:
                    response = self.http_client.get(url, timeout=self.timeout)

                elapsed = time.time() - start

                if response is None:
                    return None

                return {
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "content_length": len(response.text),
                    "elapsed": elapsed,
                    "text_snippet": response.text[:200],
                }
            except Exception as e:
                logger.debug(f"[RaceCondition] Request {request_id} failed: {e}")
                return None

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [executor.submit(make_request, i) for i in range(self.concurrency)]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        return results

    def _analyze_responses(self, responses: List[Dict]) -> Optional[str]:
        """Analyze concurrent responses for race condition indicators."""
        if len(responses) < 3:
            return None

        status_codes = [r["status_code"] for r in responses]
        content_lengths = [r["content_length"] for r in responses]
        timings = [r["elapsed"] for r in responses]

        indicators = []

        # Different status codes from identical requests
        unique_statuses = set(status_codes)
        if len(unique_statuses) > 1:
            status_counts = {s: status_codes.count(s) for s in unique_statuses}
            indicators.append(f"Mixed status codes: {status_counts}")

        # Significant content length variance
        if content_lengths:
            avg_length = sum(content_lengths) / len(content_lengths)
            if avg_length > 0:
                max_deviation = max(abs(cl - avg_length) / avg_length for cl in content_lengths)
                if max_deviation > 0.3:
                    indicators.append(
                        f"Content length variance: min={min(content_lengths)}, "
                        f"max={max(content_lengths)}, avg={avg_length:.0f}"
                    )

        # Timing anomalies (some requests much slower = contention)
        if timings:
            avg_time = sum(timings) / len(timings)
            max_time = max(timings)
            if avg_time > 0 and max_time > avg_time * 3:
                indicators.append(
                    f"Timing anomaly: avg={avg_time:.3f}s, max={max_time:.3f}s "
                    f"(possible lock contention)"
                )

        # Check for state corruption indicators in response texts
        corruption_keywords = [
            'duplicate', 'already redeemed', 'already used', 'already exists',
            'insufficient', 'negative balance', 'negative', 'conflict',
            'contention', 'deadlock', 'race', 'concurrent',
            'out of stock', 'overlap', 'double', 'multiple submission',
            'please retry', 'try again', 'locked', 'contended'
        ]
        found_keywords = []
        for r in responses:
            text = r.get('text_snippet', '').lower()
            for kw in corruption_keywords:
                if kw in text and kw not in found_keywords:
                    found_keywords.append(kw)

        if found_keywords:
            indicators.append(f"State corruption indicators found: {found_keywords}")

        if indicators:
            return "; ".join(indicators)
        return None
