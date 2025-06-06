import json
import logging
import os
from datetime import datetime
from typing import List, Dict

from colorama import Fore, Style
from termcolor import colored

class ReportGenerator:
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.results = []
        
    def add_result(self, result: Dict):
        """Add a scan result to the report"""
        self.results.append(result)
        
    def generate_json_report(self, results: List[Dict] = None):
        """Generate JSON report of scan results"""
        results_to_save = results or self.results
        try:
            with open(self.output_file, 'w') as f:
                json.dump(results_to_save, f, indent=2)
            logging.info(f"JSON report saved to {self.output_file}")
        except Exception as e:
            logging.error(f"Error saving JSON report: {str(e)}")
            
    def generate_terminal_report(self, results: List[Dict] = None):
        """Print scan results to terminal with color coding"""
        results_to_show = results or self.results
        
        if not results_to_show:
            print(colored("\n[-] No vulnerabilities found", "yellow"))
            return
            
        print(colored("\n[+] Open Redirect Vulnerabilities Found:", "green"))
        print(colored("=" * 80, "blue"))
        
        for result in results_to_show:
            print(colored(f"\nURL: {result['url']}", "cyan"))
            print(colored(f"Parameter: {result['param']}", "magenta"))
            print(colored(f"Payload: {result['payload']}", "yellow"))
            print(colored(f"Status Code: {result['status']}", "green" if result['vulnerable'] else "red"))
            print(colored(f"Redirect Location: {result['redirect_location']}", "red"))
            print(colored("-" * 60, "blue"))
            
    def generate_html_report(self, output_file: str = None):
        """Generate HTML report of scan results"""
        output_file = output_file or self.output_file.replace('.json', '.html')
        results = self.results
        
        try:
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>OpenRedirect Pro Scan Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #d9534f; }
                    .vulnerability { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
                    .url { color: #337ab7; font-weight: bold; }
                    .param { color: #5bc0de; }
                    .payload { color: #f0ad4e; }
                    .vulnerable { color: #d9534f; font-weight: bold; }
                    .safe { color: #5cb85c; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                </style>
            </head>
            <body>
                <h1>OpenRedirect Pro Scan Report</h1>
                <p>Generated on: {date}</p>
                <p>Total Vulnerabilities Found: {count}</p>
                <table>
                    <tr>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Payload</th>
                        <th>Status</th>
                        <th>Redirect Location</th>
                    </tr>
                    {rows}
                </table>
            </body>
            </html>
            """
            
            rows = ""
            for result in results:
                status_class = "vulnerable" if result['vulnerable'] else "safe"
                status_text = "VULNERABLE" if result['vulnerable'] else "Safe"
                
                rows += f"""
                <tr>
                    <td class="url">{result['url']}</td>
                    <td class="param">{result['param']}</td>
                    <td class="payload">{result['payload']}</td>
                    <td class="{status_class}">{status_text} ({result['status']})</td>
                    <td>{result['redirect_location']}</td>
                </tr>
                """
                
            html = html.replace("{date}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            html = html.replace("{count}", str(len(results)))
            html = html.replace("{rows}", rows)
            
            with open(output_file, 'w') as f:
                f.write(html)
                
            logging.info(f"HTML report saved to {output_file}")
            
        except Exception as e:
            logging.error(f"Error generating HTML report: {str(e)}")
