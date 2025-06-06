import asyncio
import re
import logging
from typing import List, Set, Optional
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

import httpx
from bs4 import BeautifulSoup

from core.utils import random_user_agent
from core.payloads import REDIRECT_PARAMS

class URLFetcher:
    def __init__(self):
        self.redirect_params = REDIRECT_PARAMS
        self.client = None
        self.timeout = 20
        self.max_retries = 2
        self.semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
        
    async def initialize_client(self):
        """Initialize HTTP client with proper headers"""
        headers = {
            "User-Agent": random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        self.client = httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            limits=limits,
            follow_redirects=False,
            verify=False
        )
        
    async def close(self):
        """Close the HTTP client"""
        if self.client:
            await self.client.aclose()
            
    async def fetch_urls(self, target: str) -> Set[str]:
        """
        Discover URLs with potential redirect parameters for a given target
        :param target: Domain or URL to scan
        :return: Set of URLs with potential redirect parameters
        """
        if not self.client:
            await self.initialize_client()
            
        urls = set()
        
        # Step 1: Check if target is a URL or domain
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"https://{target}"
            parsed = urlparse(target)
            
        # Step 2: Get URLs from various sources
        sources = [
            self._fetch_from_wayback,
            self._fetch_from_google_cache,
            self._crawl_target
        ]
        
        tasks = [source(target) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logging.error(f"Error fetching URLs: {str(result)}")
                continue
            if result:
                urls.update(result)
                
        # Step 3: Filter URLs with redirect parameters
        filtered_urls = set()
        for url in urls:
            if self._has_redirect_param(url):
                filtered_urls.add(url)
                
        return filtered_urls
        
    async def _fetch_from_wayback(self, target: str) -> Set[str]:
        """Fetch historical URLs from Wayback Machine"""
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey"
            response = await self.client.get(wayback_url)
            if response.status_code == 200:
                urls = set()
                for item in response.json()[1:]:  # Skip header row
                    url = item[0]
                    urls.add(url)
                return urls
        except Exception as e:
            logging.error(f"Wayback Machine error for {target}: {str(e)}")
        return set()
        
    async def _fetch_from_google_cache(self, target: str) -> Set[str]:
        """Fetch URLs from Google Cache"""
        try:
            cache_url = f"http://webcache.googleusercontent.com/search?q=cache:{target}&strip=1&vwsrc=0"
            response = await self.client.get(cache_url)
            if response.status_code == 200:
                return self._extract_urls_from_html(response.text, target)
        except Exception as e:
            logging.error(f"Google Cache error for {target}: {str(e)}")
        return set()
        
    async def _crawl_target(self, target: str) -> Set[str]:
        """Crawl the target website to discover URLs"""
        try:
            response = await self.client.get(target)
            if response.status_code == 200:
                return self._extract_urls_from_html(response.text, target)
        except Exception as e:
            logging.error(f"Crawling error for {target}: {str(e)}")
        return set()
        
    def _extract_urls_from_html(self, html: str, base_url: str) -> Set[str]:
        """Extract all URLs from HTML content"""
        urls = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract from common tags
        tags = {
            'a': 'href',
            'link': 'href',
            'script': 'src',
            'img': 'src',
            'iframe': 'src',
            'form': 'action'
        }
        
        parsed_base = urlparse(base_url)
        base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        for tag, attr in tags.items():
            for element in soup.find_all(tag, {attr: True}):
                url = element[attr]
                if not url.startswith(('http://', 'https://')):
                    url = base_domain + ('' if url.startswith('/') else '/') + url
                urls.add(url)
                
        return urls
        
    def _has_redirect_param(self, url: str) -> bool:
        """Check if URL contains any known redirect parameters"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        # Check for direct parameter matches
        for param in self.redirect_params:
            if param in query:
                return True
                
        # Check for parameter patterns (like redirect_uri, callback, etc.)
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
        
        for param in query.keys():
            for pattern in param_patterns:
                if re.fullmatch(pattern, param, re.IGNORECASE):
                    return True
                    
        return False
