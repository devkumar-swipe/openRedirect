import asyncio
import logging
import random
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
from tqdm.asyncio import tqdm_asyncio

from core.payloads import PAYLOADS
from core.utils import random_user_agent, is_similar_redirect

class OpenRedirectScanner:
    def __init__(self, threads: int = 10, timeout: int = 15, proxies: List[str] = None):
        self.threads = threads
        self.timeout = timeout
        self.proxies = proxies or []
        self.current_proxy = None
        self.client = None
        self.semaphore = asyncio.Semaphore(threads)
        self.tested_urls = set()
        self.vulnerable_urls = set()
        
    async def initialize_client(self):
        """Initialize HTTP client with proper configuration"""
        headers = {
            "User-Agent": random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        limits = httpx.Limits(max_keepalive_connections=self.threads, max_connections=self.threads*2)
        
        # Configure proxy if available
        proxies_config = None
        if self.proxies:
            self.current_proxy = random.choice(self.proxies)
            proxies_config = {
                "http://": self.current_proxy,
                "https://": self.current_proxy
            }
        
        self.client = httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            limits=limits,
            follow_redirects=False,
            verify=False,
            proxies=proxies_config
        )
        
    async def close(self):
        """Close the HTTP client"""
        if self.client:
            await self.client.aclose()
            
    async def scan_urls(self, urls: Set[str]) -> List[Dict]:
        """
        Scan a list of URLs for open redirect vulnerabilities
        :param urls: Set of URLs to scan
        :return: List of vulnerability findings
        """
        if not self.client:
            await self.initialize_client()
            
        # Create tasks for all URLs and payloads
        tasks = []
        for url in urls:
            if url in self.tested_urls:
                continue
                
            self.tested_urls.add(url)
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            # Find all redirect parameters in the URL
            redirect_params = self._identify_redirect_params(query)
            if not redirect_params:
                continue
                
            # Create tasks for each parameter and payload combination
            for param in redirect_params:
                original_value = query[param][0]
                for payload in PAYLOADS:
                    task = self._test_redirect(url, param, original_value, payload)
                    tasks.append(task)
                    
        # Process tasks with progress bar
        results = []
        if tasks:
            try:
                for task in tqdm_asyncio.as_completed(tasks, total=len(tasks), desc="Scanning URLs"):
                    result = await task
                    if result:
                        results.append(result)
            except Exception as e:
                logging.error(f"Error during scanning: {str(e)}")
                
        return results
        
    async def _test_redirect(self, url: str, param: str, original_value: str, payload: str) -> Optional[Dict]:
        """
        Test a single URL with a specific payload for open redirect vulnerability
        :param url: URL to test
        :param param: Parameter to inject payload into
        :param original_value: Original parameter value
        :param payload: Payload to test
        :return: Vulnerability details if found, None otherwise
        """
        async with self.semaphore:
            try:
                # Construct the malicious URL
                malicious_url = self._inject_payload(url, param, payload)
                
                # Send request and analyze response
                response = await self.client.get(malicious_url)
                
                # Check for redirect status codes
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('location', '')
                    
                    # Check if the location header matches our payload
                    if self._is_vulnerable_redirect(location, payload):
                        # Verify with a second request to avoid false positives
                        if await self._confirm_vulnerability(malicious_url):
                            return {
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "status": response.status_code,
                                "redirect_location": location,
                                "original_value": original_value,
                                "vulnerable": True
                            }
                            
                # Check for meta refresh redirects
                if response.status_code == 200:
                    if self._check_meta_refresh(response.text, payload):
                        return {
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "status": 200,
                            "redirect_location": "META-REFRESH",
                            "original_value": original_value,
                            "vulnerable": True
                        }
                        
                # Check for JavaScript redirects
                if self._check_javascript_redirect(response.text, payload):
                    return {
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "status": 200,
                        "redirect_location": "JAVASCRIPT",
                        "original_value": original_value,
                        "vulnerable": True
                    }
                    
            except httpx.TimeoutException:
                logging.warning(f"Timeout while testing: {url}")
            except httpx.RequestError as e:
                logging.warning(f"Request error for {url}: {str(e)}")
            except Exception as e:
                logging.error(f"Unexpected error testing {url}: {str(e)}")
                
            return None
            
    async def _confirm_vulnerability(self, url: str) -> bool:
        """
        Confirm a vulnerability by sending a second request with a different payload
        :param url: URL to confirm
        :return: True if confirmed vulnerable, False otherwise
        """
        try:
            response = await self.client.get(url)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('location', '')
                return "evil.com" in location or "attacker.com" in location
        except Exception:
            return False
            
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """
        Inject a payload into a URL parameter
        :param url: Original URL
        :param param: Parameter to inject into
        :param payload: Payload to inject
        :return: Modified URL with injected payload
        """
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        # Replace the parameter value with our payload
        query[param] = [payload]
        
        # Rebuild the URL
        new_query = urlencode(query, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
    def _identify_redirect_params(self, query_params: Dict) -> List[str]:
        """
        Identify parameters that could be used for redirects
        :param query_params: Dictionary of query parameters
        :return: List of potential redirect parameters
        """
        redirect_params = []
        param_patterns = [
            r'.*redirect.*',
            r'.*url.*',
            r'.*next.*',
            r'.*target.*',
            r'.*return.*',
            r'.*rurl.*',
            r'.*dest.*',
            r'.*destination.*',
            r'.*go.*',
            r'.*checkout.*',
            r'.*continue.*',
            r'.*callback.*',
            r'.*forward.*',
            r'.*link.*',
            r'.*file.*',
            r'.*page.*',
            r'.*uri.*',
            r'.*path.*'
        ]
        
        for param in query_params.keys():
            # Check exact matches first
            if param.lower() in PAYLOADS:
                redirect_params.append(param)
                continue
                
            # Check pattern matches
            for pattern in param_patterns:
                if re.fullmatch(pattern, param, re.IGNORECASE):
                    redirect_params.append(param)
                    break
                    
        return redirect_params
        
    def _is_vulnerable_redirect(self, location: str, payload: str) -> bool:
        """
        Check if a Location header indicates a vulnerable redirect
        :param location: Location header value
        :param payload: Original payload used
        :return: True if vulnerable, False otherwise
        """
        if not location:
            return False
            
        # Check if location matches our payload domain
        if "evil.com" in location or "attacker.com" in location:
            return True
            
        # Check for protocol-relative URLs
        if location.startswith('//') and ('evil.com' in location or 'attacker.com' in location):
            return True
            
        # Check for URL-encoded payloads
        decoded_location = urllib.parse.unquote(location)
        if "evil.com" in decoded_location or "attacker.com" in decoded_location:
            return True
            
        # Check for partial matches (common with sanitization)
        if is_similar_redirect(location, payload):
            return True
            
        return False
        
    def _check_meta_refresh(self, html: str, payload: str) -> bool:
        """
        Check for meta refresh redirects in HTML content
        :param html: HTML content to check
        :param payload: Original payload used
        :return: True if meta refresh redirect found, False otherwise
        """
        soup = BeautifulSoup(html, 'html.parser')
        meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
        
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if content:
                url = content.split('url=')[-1] if 'url=' in content else content.split(';')[-1]
                return self._is_vulnerable_redirect(url.strip(), payload)
                
        return False
        
    def _check_javascript_redirect(self, html: str, payload: str) -> bool:
        """
        Check for JavaScript redirects in HTML content
        :param html: HTML content to check
        :param payload: Original payload used
        :return: True if JavaScript redirect found, False otherwise
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
            for match in matches:
                if self._is_vulnerable_redirect(match, payload):
                    return True
                    
        return False
