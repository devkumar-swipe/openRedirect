# 🛡️ OpenRedirect Pro Scanner 2050 — Elite Edition

> Advanced Open Redirect vulnerability scanner built for **bug bounty hunters**, **penetration testers**, and **security researchers**.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)

---

## 🚀 Features

- 🎯 **Targeted Scanning** for open redirect vulnerabilities
- 🧠 **Smart Payload Injection** with hundreds of bypass techniques
- 🔎 **Historical URL Discovery** using Wayback Machine, Google Cache, and crawling
- 🔐 **Proxy Support** with automatic validation
- 💻 **Multi-threaded Async Engine** using `httpx` and `asyncio`
- 📊 **Comprehensive Reports** in JSON, Terminal, and HTML formats
- 📝 **Logging & Resume Support** for large-scope recon campaigns
- 🔌 **Modular Architecture** for easy extension (Playwright, Web GUI, etc.)

---

## 🏗️ Project Structure

openredirect-pro/
- ├── main.py # CLI handler
- ├── core/ # Core modules
- │ ├── scanner.py
- │ ├── fetcher.py
- │ ├── payloads.py
- │ ├── analyzer.py
- │ ├── utils.py
- │ └── reporter.py
- ├── data/ # Payloads & redirect param keywords
- │ ├── payloads.txt
- │ └── redirect-params.txt
- ├── logs/ # Resume support
- │ └── scan.log
- ├── output/ # Results folder
- │ ├── results.json
- │ └── results.html
- ├── requirements.txt
- └── README.md

---

## 📦 Installation

```bash
git clone https://github.com/devkumar-swipe/openRedirect.git
cd openRedirect
pip install -r requirements.txt
```
### Optional Dependencies (for better URL discovery)
Install these tools (Go required):

```bash
go install github.com/lc/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```
## Usage
```bash
python main.py --list targets.txt --threads 20 --output results.json
```
## CLI Options
Flag	Description
| Flag         | Description                                   |
| ------------ | --------------------------------------------- |
| `--list`     | File containing list of subdomains or URLs    |
| `--threads`  | Number of concurrent threads (default: 10)    |
| `--output`   | Output file path for results (JSON format)    |
| `--proxy`    | File with list of HTTP/SOCKS proxies          |
| `--resume`   | Resume scan from last state using `scan.log`  |
| `--timeout`  | HTTP request timeout in seconds (default: 15) |
| `--verbose`  | Enable verbose logging                        |
| `--no-color` | Disable colored output in terminal            |


## Input Files
targets.txt: Your list of subdomains or URLs (1 per line)

data/payloads.txt: Open redirect payloads (fully customizable)

data/redirect-params.txt: Redirect-related query parameter names

data/proxy.txt: (Optional) List of HTTP/SOCKS proxies

## Output
results.json: All detected vulnerabilities (structured format)

results.html: (Optional) User-friendly visual report

Terminal Output: Color-coded, real-time vulnerability log

## 🧪 Example
```bash
python main.py --list data/targets.txt --threads 20 --proxy data/proxy.txt --output output/results.json --resume
```
## Payload Examples
The scanner includes hundreds of payloads designed for real-world bypasses, such as:

-https://evil.com
-//evil.com
-javascript:alert(1)
-http://127.0.0.1
-data:text/html,<script>alert(1)</script>
-http://evil.com#example.com

You can fully customize payloads in data/payloads.txt.

## 🔄 Resume Scans
If your scan was interrupted or had a large scope:

```bash
python main.py --list data/targets.txt --resume
```
The scanner reads from logs/scan.log and skips already-tested URLs.

## 🧱 Built With
httpx, asyncio — Async, fast scanning

beautifulsoup4 — HTML parsing for JS/meta redirects

colorama, termcolor — Terminal UI

tqdm — Progress bars

PyYAML, dotenv — Config flexibility

## 🧩 Future Extensions
 Playwright integration for browser-based redirect detection

 Web-based dashboard to monitor scans visually

 AI-based redirect filtering

 Auto-integrate with subfinder, amass, hakrawler

## 🤝 Contributing
Pull requests, ideas, and issues are welcome!
To contribute:

- Fork this repo
- Make your changes
- Open a PR 🚀

## 🧑‍💻 Author
Dev Kumar
Ethical Hacker & Security Researcher
✉️ Email: devkumarmahto204@outlook.com

📜 License
This project is licensed under the MIT License.

📸 Screenshots / Demos
