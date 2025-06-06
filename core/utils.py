import asyncio
import logging
import os
import random
import re
import time
from pathlib import Path
from typing import List, Optional, Set

import httpx
import yaml
from colorama import Fore, Style
from dotenv import load_dotenv
from termcolor import colored

# Load environment variables
load_dotenv()

# Common user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
]

def random_user_agent() -> str:
    """Return a random user agent string"""
    return random.choice(USER_AGENTS)

def setup_logging(log_file: str, verbose: bool = False):
    """Configure logging for the application"""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
def create_directory_structure():
    """Create necessary directories if they don't exist"""
    directories = [
        "logs",
        "output",
        "data",
        "core"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        
def load_proxies(proxy_file: str) -> List[str]:
    """Load proxies from a file"""
    try:
        with open(proxy_file, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        return proxies
    except Exception as e:
        logging.error(f"Error loading proxies: {str(e)}")
        return []
        
async def validate_proxies(proxies: List[str]) -> List[str]:
    """Validate a list of proxies by testing them against a known URL"""
    valid_proxies = []
    test_url = "https://www.google.com"
    
    async def test_proxy(proxy: str) -> Optional[str]:
        try:
            async with httpx.AsyncClient(
                proxies={"http://": proxy, "https://": proxy},
                timeout=10,
                verify=False
            ) as client:
                response = await client.get(test_url)
                if response.status_code == 200:
                    return proxy
        except Exception:
            return None
            
    tasks = [test_proxy(proxy) for proxy in proxies]
    results = await asyncio.gather(*tasks)
    
    valid_proxies = [proxy for proxy in results if proxy is not None]
    return valid_proxies
    
def read_file_lines(file_path: str) -> List[str]:
    """Read lines from a file and return as list, skipping empty lines"""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        return []
        
def get_tested_urls_from_log(log_file: str) -> Set[str]:
    """Extract already tested URLs from log file"""
    tested_urls = set()
    
    if not os.path.isfile(log_file):
        return tested_urls
        
    try:
        with open(log_file, 'r') as f:
            for line in f:
                if "Testing URL:" in line:
                    url = line.split("Testing URL:")[1].strip()
                    tested_urls.add(url)
    except Exception as e:
        logging.error(f"Error reading log file: {str(e)}")
        
    return tested_urls
    
def is_similar_redirect(location: str, payload: str) -> bool:
    """
    Check if a Location header is similar to our payload (for partial matches)
    :param location: Location header value
    :param payload: Original payload used
    :return: True if similar, False otherwise
    """
    # Check if payload domain appears in location
    payload_domain = extract_domain(payload)
    if payload_domain and payload_domain in location:
        return True
        
    # Check for protocol-relative versions
    if payload.startswith('//') and payload[2:] in location:
        return True
        
    # Check for URL-encoded versions
    try:
        decoded_location = urllib.parse.unquote(location)
        if payload in decoded_location:
            return True
    except:
        pass
        
    # Check for common sanitization patterns
    sanitized_payload = payload.replace('http://', '').replace('https://', '')
    if sanitized_payload in location:
        return True
        
    return False
    
def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from a URL
    :param url: URL to parse
    :return: Domain or None
    """
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        elif url.startswith('//'):
            return url[2:].split('/')[0]
        else:
            return None
    except:
        return None
        
def print_banner():
    """Print the tool banner"""
    banner = f"""
{Fore.RED}
   ___  ____  ____  ____  ____  _____  _____  ____  ____  ____  ____ 
  / __)(  _ \( ___)(  _ \( ___)(  _  )(  _  )(  _ \( ___)(  _ \( ___)
 ( (__  )   / )__)  )   / )__)  )(_)(  )(_)(  )___/ )__)  )   / )__) 
  \___)(_)\_)(____)(_)\_)(____)(_____)(_____)(__)  (____)(_)\_)(____)
  
  {Fore.YELLOW}OpenRedirect Pro Scanner 2050 — {Fore.CYAN}Elite Edition{Fore.RESET}
  
  {Fore.GREEN}Advanced Open Redirect Vulnerability Scanner{Fore.RESET}
  {Fore.MAGENTA}By BugHunterPro | {Fore.BLUE}https://github.com/bughunterpro{Fore.RESET}
"""
    print(banner)
