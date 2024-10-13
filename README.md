# CNAME-Sniffer
CNAME Sniffer is a subdomain takeover tool designed to help identify subdomains with vulnerable CNAME records that can be exploited for takeover purposes.
# CNAME Sniffer

CNAME Sniffer is a powerful subdomain takeover tool designed to help security professionals and bug bounty hunters detect vulnerable CNAME records associated with unclaimed subdomains. The tool performs automated scanning of subdomains and checks for misconfigurations in DNS that could potentially be exploited to take over the subdomain.

> **Note**: This tool is intended for educational purposes only. Please use it responsibly and only test in authorized environments.

## Features
- Scans for subdomains with vulnerable CNAME records.
- Uses publicly available payloads and methods for takeover attempts.
- Lightweight and easy to use.

## Prerequisites

Before using this tool, you will need the following:
- Python 3.x
- Install the required Python packages with `pip install -r requirements.txt`

## Requirements

This tool uses the following Python libraries:
- `colorama` (for colored output)
- `requests` (for HTTP requests)
- `dnspython` (for DNS queries)

To install these dependencies, run:
```
pip install -r requirements.txt

Usage
To start using CNAME Sniffer, you need to provide the input file containing the list of subdomains.

Command Syntax:
python3 cname_sniffer.py -f <file_with_subdomains>

Example:
python3 cname_sniffer.py -f subdomains.txt

This will scan the subdomains listed in the file and identify any vulnerable CNAME records that could be exploited for subdomain takeover.


Legal Disclaimer
This tool is intended only for educational purposes and for testing in authorized environments. The developers take no responsibility for any misuse of this code. Use it at your own risk. Ensure that you have permission to test the target you are engaging with.

