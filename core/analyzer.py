import re
import logging
from typing import Dict, Optional
from urllib.parse import urlparse

class ResponseAnalyzer:
    @staticmethod
    def is_open_redirect(response: Dict, payload: str) -> bool:
        """
        Determine if a response indicates an open redirect vulnerability
        :param response: Dictionary containing response details
        :param payload: Original payload used
        :return: True if vulnerable, False otherwise
        """
        status = response.get('status_code')
        headers = response.get('headers', {})
        text = response.get('text', '')
        
        # Check HTTP redirect status codes
        if status in (301, 302, 303, 307, 308):
            location = headers.get('location', '')
            if ResponseAnalyzer._is_malicious_location(location, payload):
                return True
                
        # Check meta refresh redirects
        if ResponseAnalyzer._has_malicious_meta_refresh(text, payload):
            return True
            
        # Check JavaScript redirects
        if ResponseAnalyzer._has_malicious_javascript(text, payload):
            return True
            
        return False
        
    @staticmethod
    def _is_malicious_location(location: str, payload: str) -> bool:
        """
        Check if Location header contains malicious redirect
        :param location: Location header value
        :param payload: Original payload used
        :return: True if malicious, False otherwise
        """
        if not location:
            return False
            
        # Check for direct matches
        malicious_domains = ['evil.com', 'attacker.com']
        for domain in malicious_domains:
            if domain in location:
                return True
                
        # Check for protocol-relative URLs
        if location.startswith('//') and any(domain in location for domain in malicious_domains):
            return True
            
        # Check for URL-encoded payloads
        try:
            decoded = urllib.parse.unquote(location)
            if any(domain in decoded for domain in malicious_domains):
                return True
        except:
            pass
            
        # Check for similar redirects (common with sanitization)
        if ResponseAnalyzer._is_similar_redirect(location, payload):
            return True
            
        return False
        
    @staticmethod
    def _is_similar_redirect(location: str, payload: str) -> bool:
        """
        Check if Location header is similar to our payload (for partial matches)
        :param location: Location header value
        :param payload: Original payload used
        :return: True if similar, False otherwise
        """
        # Implement similarity checks here
        # This could include checking for partial matches, domain fragments, etc.
        return False
        
    @staticmethod
    def _has_malicious_meta_refresh(html: str, payload: str) -> bool:
        """
        Check for meta refresh redirects in HTML content
        :param html: HTML content
        :param payload: Original payload used
        :return: True if malicious meta refresh found, False otherwise
        """
        meta_refresh_pattern = re.compile(
            r'<meta\s+http-equiv=["\']?refresh["\']?\s+content=["\']?\d+;\s*url=([^"\'>]+)',
            re.IGNORECASE
        )
        
        matches = meta_refresh_pattern.findall(html)
        for url in matches:
            if ResponseAnalyzer._is_malicious_location(url.strip(), payload):
                return True
                
        return False
        
    @staticmethod
    def _has_malicious_javascript(html: str, payload: str) -> bool:
        """
        Check for JavaScript redirects in HTML content
        :param html: HTML content
        :param payload: Original payload used
        :return: True if malicious JavaScript redirect found, False otherwise
        """
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.replace\s*\(["\']([^"\']+)["\']\)',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\s*\(["\']([^"\']+)["\']\)',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(["\']([^"\']+)["\']',
            r'window\.navigate\s*\(["\']([^"\']+)["\']\)'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for url in matches:
                if ResponseAnalyzer._is_malicious_location(url, payload):
                    return True
                    
        return False
