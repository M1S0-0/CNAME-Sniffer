
# CNAME Sniffer

CNAME Sniffer is a subdomain takeover tool designed to help identify subdomains with vulnerable CNAME records that can be exploited for takeover purposes.

## Overview

CNAME Sniffer is a powerful subdomain takeover tool built for security professionals and bug bounty hunters. It helps detect vulnerable CNAME records associated with unclaimed subdomains. The tool automates the scanning process for subdomains and checks for misconfigurations in DNS that could potentially allow an attacker to take over the subdomain.

> **Note**: This tool is intended for educational purposes only. Use it responsibly and only test in authorized environments.

## Features
- Scans subdomains for vulnerable CNAME records.
- Uses publicly available payloads and methods for takeover attempts.
- Lightweight and simple to use.

## Requirements

This tool uses the following Python libraries:
- `colorama` (for colored output)
- `requests` (for HTTP requests)
- `dnspython` (for DNS queries)

## Prerequisites

Before using CNAME Sniffer, make sure you have:
- **Python 3.x** installed on your machine.
- The required Python packages (install using the command below).

##  Usage
- To use CNAME Sniffer, provide an input file containing the list of subdomains you want to scan.

## Supported Services for Subdomain Takeover:
- AWS S3
- GitHub Pages
- Heroku
- Shopify
- Tumblr
- Azure
- Bitbucket
- Fastly
- Ghost
- And many more...

## Command Syntax
- python3 cname_sniffer.py -f <file_with_subdomains>

 This will scan the subdomains listed in the file and identify any vulnerable CNAME records that could be exploited for subdomain takeover.

## Legal Disclaimer
This tool is intended only for educational purposes and for testing in authorized environments. The developers, **M1S0** and [https://x.com/UnknownMnz](https://x.com/UnknownMnz), take no responsibility for any misuse of this code. Use it at your own risk. Ensure you have permission to test the target you are engaging with.


## Installation

First, clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/M1S0-0/CNAME-Sniffer.git
cd CNAME_Sniffer
pip install -r requirements.txt   [If you already have packages, don't use this command.]
chmod +x cname_sniffer.py 
python3 cname_sniffer.py -f subdomains_list.txt


