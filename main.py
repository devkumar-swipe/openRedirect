
#Now let's implement the core modules:

## 2. main.py - CLI Interface

#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from colorama import init, Fore
from termcolor import colored

from core.fetcher import URLFetcher
from core.scanner import OpenRedirectScanner
from core.reporter import ReportGenerator
from core.utils import (
    setup_logging,
    load_proxies,
    validate_proxies,
    read_file_lines,
    should_resume,
    get_tested_urls_from_log,
    create_directory_structure
)

# Initialize colorama
init()

class OpenRedirectPro:
    def __init__(self):
        self.banner = f"""
{Fore.RED}
       ▄▄▄·▄▄▄ . ▐ ▄     ▄▄▄  ▄▄▄ .·▄▄▄▄  ▪  ▄▄▄  ▄▄▄ . ▄▄· ▄▄▄▄▄
▪     ▐█ ▄█▀▄.▀·•█▌▐█    ▀▄ █·▀▄.▀·██▪ ██ ██ ▀▄ █·▀▄.▀·▐█ ▌▪•██  
 ▄█▀▄  ██▀·▐▀▀▪▄▐█▐▐▌    ▐▀▀▄ ▐▀▀▪▄▐█· ▐█▌▐█·▐▀▀▄ ▐▀▀▪▄██ ▄▄ ▐█.▪
▐█▌.▐▌▐█▪·•▐█▄▄▌██▐█▌    ▐█•█▌▐█▄▄▌██. ██ ▐█▌▐█•█▌▐█▄▄▌▐███▌ ▐█▌·
 ▀█▄▀▪.▀    ▀▀▀ ▀▀ █▪    .▀  ▀ ▀▀▀ ▀▀▀▀▀• ▀▀▀.▀  ▀ ▀▀▀ ·▀▀▀  ▀▀▀ 
  
  {Fore.YELLOW}OpenRedirect Pro Scanner 2050 — {Fore.CYAN}Elite Edition{Fore.RESET}
  
  {Fore.GREEN}Advanced Open Redirect Vulnerability Scanner{Fore.RESET}
  {Fore.MAGENTA}By BugHunterPro | {Fore.BLUE}https://github.com/bughunterpro{Fore.RESET}
"""

    def parse_args(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="OpenRedirect Pro Scanner - Advanced Open Redirect Vulnerability Detection",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument(
            "--list", 
            required=True,
            help="File containing list of subdomains or URLs to test"
        )
        parser.add_argument(
            "--threads", 
            type=int, 
            default=10,
            help="Number of concurrent threads to use"
        )
        parser.add_argument(
            "--output", 
            default="results.json",
            help="Output file to save results (JSON format)"
        )
        parser.add_argument(
            "--proxy", 
            help="File containing list of proxies (HTTP/SOCKS)"
        )
        parser.add_argument(
            "--resume", 
            action="store_true",
            help="Resume scanning from the last state using logs"
        )
        parser.add_argument(
            "--timeout", 
            type=int, 
            default=15,
            help="Timeout for HTTP requests in seconds"
        )
        parser.add_argument(
            "--verbose", 
            action="store_true",
            help="Enable verbose output"
        )
        parser.add_argument(
            "--no-color", 
            action="store_true",
            help="Disable colored output"
        )
        return parser.parse_args()

    async def run(self):
        print(self.banner)
        args = self.parse_args()
        
        # Setup logging
        log_file = "logs/scan.log"
        setup_logging(log_file, args.verbose)
        
        # Create required directories
        create_directory_structure()
        
        # Validate input file
        if not os.path.isfile(args.list):
            logging.error(f"Input file not found: {args.list}")
            print(colored(f"[!] Input file not found: {args.list}", "red"))
            sys.exit(1)
            
        # Load targets
        targets = read_file_lines(args.list)
        if not targets:
            logging.error("No targets found in input file")
            print(colored("[!] No targets found in input file", "red"))
            sys.exit(1)
            
        # Handle proxy configuration
        proxies = []
        if args.proxy:
            if not os.path.isfile(args.proxy):
                logging.error(f"Proxy file not found: {args.proxy}")
                print(colored(f"[!] Proxy file not found: {args.proxy}", "red"))
                sys.exit(1)
                
            proxies = load_proxies(args.proxy)
            if not proxies:
                logging.error("No valid proxies found in proxy file")
                print(colored("[!] No valid proxies found in proxy file", "red"))
                sys.exit(1)
                
            logging.info(f"Loaded {len(proxies)} proxies from file")
            print(colored(f"[*] Loaded {len(proxies)} proxies", "cyan"))
            
            # Validate proxies
            valid_proxies = await validate_proxies(proxies)
            if not valid_proxies:
                logging.error("No working proxies found")
                print(colored("[!] No working proxies found", "red"))
                sys.exit(1)
                
            proxies = valid_proxies
            logging.info(f"Validated {len(proxies)} working proxies")
            print(colored(f"[*] Validated {len(proxies)} working proxies", "cyan"))
        
        # Handle resume functionality
        tested_urls = set()
        if args.resume:
            tested_urls = get_tested_urls_from_log(log_file)
            logging.info(f"Resuming scan, skipping {len(tested_urls)} already tested URLs")
            print(colored(f"[*] Resuming scan, skipping {len(tested_urls)} already tested URLs", "yellow"))
        
        # Initialize components
        fetcher = URLFetcher()
        scanner = OpenRedirectScanner(threads=args.threads, timeout=args.timeout, proxies=proxies)
        reporter = ReportGenerator(args.output)
        
        # Start scanning process
        logging.info("Starting OpenRedirect Pro scan")
        print(colored("\n[*] Starting OpenRedirect Pro scan", "blue"))
        
        try:
            # Step 1: Fetch URLs for each target
            logging.info("Discovering URLs with potential redirect parameters")
            print(colored("[*] Discovering URLs with potential redirect parameters...", "blue"))
            
            all_urls = []
            for target in targets:
                urls = await fetcher.fetch_urls(target)
                if urls:
                    all_urls.extend(urls)
            
            if not all_urls:
                logging.error("No URLs with redirect parameters found")
                print(colored("[!] No URLs with redirect parameters found", "red"))
                sys.exit(1)
                
            logging.info(f"Found {len(all_urls)} URLs with potential redirect parameters")
            print(colored(f"[*] Found {len(all_urls)} URLs with potential redirect parameters", "green"))
            
            # Step 2: Filter out already tested URLs if resuming
            if args.resume:
                all_urls = [url for url in all_urls if url not in tested_urls]
                if not all_urls:
                    logging.info("All URLs already tested, nothing to scan")
                    print(colored("[*] All URLs already tested, nothing to scan", "yellow"))
                    sys.exit(0)
                    
                logging.info(f"After resume filtering, {len(all_urls)} URLs remain to test")
                print(colored(f"[*] After resume filtering, {len(all_urls)} URLs remain to test", "yellow"))
            
            # Step 3: Scan URLs for open redirect vulnerabilities
            logging.info("Starting vulnerability scanning")
            print(colored("\n[*] Starting vulnerability scanning...", "blue"))
            
            results = await scanner.scan_urls(all_urls)
            
            # Step 4: Generate reports
            logging.info("Generating reports")
            print(colored("\n[*] Generating reports...", "blue"))
            
            reporter.generate_json_report(results)
            reporter.generate_terminal_report(results)
            
            logging.info(f"Scan completed. Results saved to {args.output}")
            print(colored(f"\n[+] Scan completed. Results saved to {args.output}", "green"))
            
        except KeyboardInterrupt:
            logging.warning("Scan interrupted by user")
            print(colored("\n[!] Scan interrupted by user", "yellow"))
            sys.exit(1)
            
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}", exc_info=True)
            print(colored(f"\n[!] Unexpected error: {str(e)}", "red"))
            sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(OpenRedirectPro().run())
    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user", "yellow"))
        sys.exit(1)
