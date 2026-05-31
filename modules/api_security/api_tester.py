"""
API Security Testing Module
Tests REST APIs, GraphQL, and other API endpoints for security vulnerabilities
"""

import json
from typing import Dict, List, Optional
from urllib.parse import urljoin
from utils.logger import get_logger

logger = get_logger(__name__)


class APISecurityTester:
    """Comprehensive API security testing."""
    
    def __init__(self, http_client, config: Dict):
        """Initialize API security tester."""
        self.http_client = http_client
        self.config = config
        
    def test_api_endpoint(self, url: str, context: Dict) -> List[Dict]:
        """
        Test API endpoint for security vulnerabilities.
        
        Args:
            url: API endpoint URL
            context: Request context
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Test for various API vulnerabilities
        vulnerabilities.extend(self._test_broken_authentication(url, context))
        vulnerabilities.extend(self._test_excessive_data_exposure(url))
        vulnerabilities.extend(self._test_lack_of_resources(url))
        vulnerabilities.extend(self._test_broken_object_level_auth(url, context))
        vulnerabilities.extend(self._test_mass_assignment(url, context))
        vulnerabilities.extend(self._test_security_misconfiguration(url))
        vulnerabilities.extend(self._test_injection(url))
        vulnerabilities.extend(self._test_improper_assets_management(url))
        vulnerabilities.extend(self._test_insufficient_logging(url))
        
        return vulnerabilities
    
    def _test_broken_authentication(self, url: str, context: Dict) -> List[Dict]:
        """Test for broken authentication (OWASP API1:2023)."""
        vulnerabilities = []
        
        if not context.get('auth_required', False):
            return vulnerabilities
        
        # Test without authentication
        try:
            response = self.http_client.get(url)
            if response and response.status_code == 200:
                vulnerabilities.append({
                    'type': 'API Security - Broken Authentication',
                    'severity': 'critical',
                    'url': url,
                    'evidence': f'Endpoint accessible without authentication (Status: {response.status_code})',
                    'description': 'API endpoint does not require authentication',
                    'remediation': 'Implement proper authentication mechanisms (OAuth2, JWT, API keys)',
                    'owasp_category': 'API1:2023 - Broken Object Level Authorization'
                })
        except Exception as e:
            logger.debug(f"Error testing authentication: {e}")
        
        # Test with invalid tokens
        invalid_tokens = [
            'Bearer invalid_token',
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid',
            'Basic YWRtaW46YWRtaW4='
        ]
        
        for token in invalid_tokens:
            try:
                response = self.http_client.get(
                    url,
                    headers={'Authorization': token}
                )
                if response and response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'API Security - Invalid Token Accepted',
                        'severity': 'high',
                        'url': url,
                        'evidence': f'Invalid token accepted: {token[:20]}...',
                        'description': 'API accepts invalid authentication tokens',
                        'remediation': 'Implement proper token validation',
                        'owasp_category': 'API1:2023'
                    })
            except Exception as e:
                logger.debug(f"Error testing invalid token: {e}")
        
        return vulnerabilities
    
    def _test_excessive_data_exposure(self, url: str) -> List[Dict]:
        """Test for excessive data exposure (OWASP API3:2023)."""
        vulnerabilities = []
        
        sensitive_fields = {
            'password', 'secret', 'api_key', 'ssn',
            'credit_card', 'private_key', 'hash', 'salt'
        }
        
        placeholders = {'', '********', '****', '***', '**', '*', 'null', 'None', 'undefined'}
        
        def _walk(obj):
            findings = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        findings.extend(_walk(v))
                    elif isinstance(v, str) and k.lower() in sensitive_fields:
                        if v not in placeholders and len(v) > 4 and 'xxx' not in v.lower():
                            findings.append(k)
            elif isinstance(obj, list):
                for item in obj:
                    findings.extend(_walk(item))
            return findings
        
        try:
            response = self.http_client.get(url)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    exposed = _walk(data)
                    for field in set(exposed):
                        vulnerabilities.append({
                            'type': 'API Security - Excessive Data Exposure',
                            'severity': 'high',
                            'url': url,
                            'evidence': f'Sensitive field with actual credential value: {field}',
                            'description': 'API response contains sensitive data that should not be exposed',
                            'remediation': 'Filter response data to exclude sensitive fields',
                            'owasp_category': 'API3:2023 - Broken Object Property Level Authorization'
                        })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.debug(f"Error testing data exposure: {e}")
        
        return vulnerabilities
    
    def _test_lack_of_resources(self, url: str) -> List[Dict]:
        """Test for lack of resources & rate limiting (OWASP API4:2023)."""
        vulnerabilities = []
        
        # Test rate limiting by making multiple requests
        try:
            responses = []
            for _ in range(100):
                response = self.http_client.get(url)
                if response:
                    responses.append(response.status_code)
            
            # Check if all requests succeeded (no rate limiting)
            if all(status == 200 for status in responses):
                vulnerabilities.append({
                    'type': 'API Security - Missing Rate Limiting',
                    'severity': 'medium',
                    'url': url,
                    'evidence': '100 consecutive requests succeeded without rate limiting',
                    'description': 'API endpoint lacks rate limiting protection',
                    'remediation': 'Implement rate limiting (e.g., 100 requests per minute)',
                    'owasp_category': 'API4:2023 - Unrestricted Resource Consumption'
                })
        except Exception as e:
            logger.debug(f"Error testing rate limiting: {e}")
        
        return vulnerabilities
    
    def _test_broken_object_level_auth(self, url: str, context: Dict) -> List[Dict]:
        """Test for broken object level authorization (OWASP API1:2023)."""
        vulnerabilities = []
        
        if not context.get('authenticated_session', False):
            return vulnerabilities
        
        if any(param in url for param in ['id=', 'user=', 'account=', 'item=']):
            test_ids = ['2', '3', '999']
            
            for test_id in test_ids:
                try:
                    import re
                    test_url = re.sub(r'(id|user|account|item)=\d+', rf'\1={test_id}', url)
                    
                    response = self.http_client.get(
                        test_url,
                        headers=context.get('auth_headers', {})
                    )
                    if response and response.status_code == 200:
                        orig_response = self.http_client.get(
                            url,
                            headers=context.get('auth_headers', {})
                        )
                        if orig_response and orig_response.status_code == 200:
                            try:
                                orig_data = orig_response.json()
                                new_data = response.json()
                                if orig_data != new_data:
                                    vulnerabilities.append({
                                        'type': 'API Security - IDOR (Insecure Direct Object Reference)',
                                        'severity': 'critical',
                                        'url': url,
                                        'evidence': f'Accessing object with ID {test_id} returned different data',
                                        'description': 'API allows unauthorized access to objects by manipulating IDs',
                                        'remediation': 'Implement object-level authorization checks',
                                        'owasp_category': 'API1:2023 - Broken Object Level Authorization'
                                    })
                                    break
                            except (json.JSONDecodeError, ValueError):
                                pass
                except Exception as e:
                    logger.debug(f"Error testing IDOR: {e}")
        
        return vulnerabilities
    
    def _test_mass_assignment(self, url: str, context: Dict) -> List[Dict]:
        """Test for mass assignment vulnerabilities (OWASP API6:2023)."""
        vulnerabilities = []
        
        if not context.get('auth_required', False):
            return vulnerabilities
        
        dangerous_fields = {
            'is_admin': True,
            'role': 'admin',
            'is_verified': True,
            'account_balance': 999999,
            'permissions': ['admin', 'superuser']
        }
        
        try:
            response = self.http_client.post(url, json=dangerous_fields)
            if response and response.status_code in [200, 201]:
                try:
                    response_data = response.json()
                    if isinstance(response_data, dict):
                        if response_data.get('is_admin') == True or response_data.get('role') == 'admin':
                            vulnerabilities.append({
                                'type': 'API Security - Mass Assignment',
                                'severity': 'high',
                                'url': url,
                                'evidence': 'Admin privilege field accepted and reflected in response',
                                'description': 'API allows mass assignment of sensitive properties',
                                'remediation': 'Use allowlist for acceptable fields, implement proper input validation',
                                'owasp_category': 'API6:2023 - Unrestricted Access to Sensitive Business Flows'
                            })
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception as e:
            logger.debug(f"Error testing mass assignment: {e}")
        
        return vulnerabilities
    
    def _test_security_misconfiguration(self, url: str) -> List[Dict]:
        """Test for security misconfiguration (OWASP API8:2023)."""
        vulnerabilities = []
        
        try:
            response = self.http_client.get(url)
            if response:
                headers = response.headers
                
                # Check for verbose error messages
                if response.status_code >= 500:
                    if any(keyword in response.text.lower() for keyword in ['exception', 'stack trace', 'error at line']):
                        vulnerabilities.append({
                            'type': 'API Security - Verbose Error Messages',
                            'severity': 'medium',
                            'url': url,
                            'evidence': 'API returns detailed error messages with stack traces',
                            'description': 'Verbose error messages may leak sensitive information',
                            'remediation': 'Implement generic error messages for production',
                            'owasp_category': 'API8:2023 - Security Misconfiguration'
                        })
                
                # Check CORS policy
                if 'Access-Control-Allow-Origin' in headers:
                    if headers['Access-Control-Allow-Origin'] == '*':
                        vulnerabilities.append({
                            'type': 'API Security - Permissive CORS',
                            'severity': 'medium',
                            'url': url,
                            'evidence': 'Access-Control-Allow-Origin: *',
                            'description': 'API has overly permissive CORS policy',
                            'remediation': 'Restrict CORS to specific trusted domains',
                            'owasp_category': 'API8:2023 - Security Misconfiguration'
                        })
        except Exception as e:
            logger.debug(f"Error testing security misconfiguration: {e}")
        
        return vulnerabilities
    
    def _test_injection(self, url: str) -> List[Dict]:
        """Test for injection vulnerabilities in API."""
        vulnerabilities = []
        
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql error',
            'unclosed quotation mark', 'odbc driver', 'microsoft ole db',
            'warning: mysql', 'syntax error', 'unexpected end of sql',
            'driver error', 'db2 sql error', 'mssql error',
            'supplied argument is not a valid', 'pg_query',
            'sqlite_error', 'sqlite3::', 'division by zero',
            'unterminated string', 'unknown column'
        ]
        
        injection_payloads = {
            'sql': ["' OR '1'='1", "1; DROP TABLE users--"],
            'nosql': ['{"$gt":""}', '{"$ne":null}'],
            'command': ['; ls -la', '| whoami']
        }
        
        for injection_type, payloads in injection_payloads.items():
            for payload in payloads:
                try:
                    response = self.http_client.post(
                        url,
                        json={'query': payload, 'input': payload}
                    )
                    
                    if response:
                        text_lower = response.text.lower()
                        if injection_type == 'sql':
                            if any(err in text_lower for err in sql_errors):
                                vulnerabilities.append({
                                    'type': 'API Security - SQL Injection',
                                    'severity': 'critical',
                                    'url': url,
                                    'payload': payload,
                                    'evidence': f'Database error detected with SQL injection payload',
                                    'description': 'API endpoint vulnerable to SQL injection',
                                    'remediation': 'Use parameterized queries and input validation',
                                    'owasp_category': 'API8:2023 - Security Misconfiguration'
                                })
                                break
                        elif injection_type in ('nosql', 'command') and response.status_code == 200:
                            vulnerabilities.append({
                                'type': f'API Security - {injection_type.upper()} Injection',
                                'severity': 'critical',
                                'url': url,
                                'payload': payload,
                                'evidence': f'API accepted {injection_type} injection payload',
                                'description': f'API endpoint may be vulnerable to {injection_type} injection attacks',
                                'remediation': 'Use parameterized queries and input validation',
                                'owasp_category': 'API8:2023 - Security Misconfiguration'
                            })
                            break
                except Exception as e:
                    logger.debug(f"Error testing {injection_type} injection: {e}")
        
        return vulnerabilities
    
    def _test_improper_assets_management(self, url: str) -> List[Dict]:
        """Test for improper assets management (OWASP API9:2023)."""
        vulnerabilities = []
        
        # Test old API versions
        version_patterns = ['/v1/', '/v2/', '/api/v1/', '/api/v2/', '/1.0/', '/2.0/']
        
        for version in version_patterns:
            if version in url:
                # Try accessing without version or older versions
                test_urls = [
                    url.replace(version, '/'),
                    url.replace(version, '/v0/'),
                    url.replace(version, '/old/')
                ]
                
                for test_url in test_urls:
                    try:
                        response = self.http_client.get(test_url)
                        if response and response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'API Security - Old API Version Accessible',
                                'severity': 'medium',
                                'url': test_url,
                                'evidence': f'Old API version still accessible: {test_url}',
                                'description': 'Outdated API versions may have unpatched vulnerabilities',
                                'remediation': 'Deprecate and remove old API versions',
                                'owasp_category': 'API9:2023 - Improper Inventory Management'
                            })
                    except Exception as e:
                        logger.debug(f"Error testing old API version: {e}")
        
        return vulnerabilities
    
    def _test_insufficient_logging(self, url: str) -> List[Dict]:
        """Test for insufficient logging & monitoring (OWASP API10:2023)."""
        vulnerabilities = []
        
        # This is difficult to test externally, but we can check for common indicators
        try:
            # Test if failed authentication attempts are handled properly
            response = self.http_client.get(
                url,
                headers={'Authorization': 'Bearer invalid_token_12345'}
            )
            
            if response and response.status_code == 200:
                # If invalid auth still succeeds, logging is likely insufficient
                vulnerabilities.append({
                    'type': 'API Security - Insufficient Logging',
                    'severity': 'low',
                    'url': url,
                    'evidence': 'Authentication failures may not be properly logged',
                    'description': 'API may lack proper logging and monitoring',
                    'remediation': 'Implement comprehensive logging for security events',
                    'owasp_category': 'API10:2023 - Unsafe Consumption of APIs'
                })
        except Exception as e:
            logger.debug(f"Error testing logging: {e}")
        
        return vulnerabilities
