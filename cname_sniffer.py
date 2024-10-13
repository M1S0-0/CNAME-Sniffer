#!/usr/bin/python3
import requests
import argparse
import dns.resolver
from bs4 import BeautifulSoup
from colorama import Fore, init
from urllib.parse import urlparse
import warnings

# Suppress InsecureRequestWarning from urllib3
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')

# Initialize colorama
init(autoreset=True)

# Print the logo representation of SubDome!!
print(Fore.MAGENTA + r"""
   ____ _   _    _   _  _____   _____ _  __ _____ ______ ______  
  / ___| \ | |  | \ | |/ _ \ \ / / _ \ |/ // ____|  ____|  ____| 
 | |   |  \| |  |  \| | | | \ V / | | | ' /| (___ | |__  | |__   
 | |   | . ` |  | . ` | | | |> <| | | |  <  \___ \|  __| |  __|  
 | |___| |\  |  | |\  | |_| |/ . \ |_| | . \ ____) | |____| |____ 
  \____|_| \_|  |_| \_|\___//_/ \_\___/|_|\_\_____/|______|______|

                S N I F F E R   
""" + Fore.RESET)


# Function to extract page title from the response content
def get_page_title(content):
    try:
        soup = BeautifulSoup(content, 'html.parser')
        title = soup.title.string if soup.title else None
        if not title and '<?xml' in content.decode('utf-8', 'ignore'):
            soup = BeautifulSoup(content, 'lxml-xml')
            title = soup.find('title')
        return title.strip() if title else 'No title'
    except Exception as e:
        print(f"Error fetching title: {e}")
        return 'Error fetching title'

# Function to resolve CNAME records of a given subdomain
def get_cname(subdomain):
    try:
        print(f"Resolving CNAME for: {subdomain}")
        parsed_url = urlparse(subdomain)
        domain = parsed_url.netloc or parsed_url.path

        # Resolve CNAME using dns.resolver
        answers = dns.resolver.resolve(domain, 'CNAME')
        cname = [rdata.target.to_text().rstrip('.') for rdata in answers]
        print(f"Resolved CNAME: {cname}")

        # Try to resolve the IP address from the CNAME
        try:
            ip_answers = dns.resolver.resolve(cname[0], 'A')
            ips = [ip.address for ip in ip_answers]
            print(f"CNAME {cname[0]} resolves to IP(s): {', '.join(ips)}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"No A records found for CNAME {cname[0]}")
        return cname
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        print(f"DNS resolution failed for {subdomain}: {e}")
        return []
    except Exception as e:
        print(f"Unknown error while resolving CNAME for {subdomain}: {e}")
        return []

# Function to check if subdomain is vulnerable to takeover based on CNAME and service patterns
def check_subdomain_takeover(subdomain, output_file):
    # Remove http:// or https:// from the subdomain
    if subdomain.startswith(('http://', 'https://')):
        subdomain = subdomain.split('://', 1)[1]  # Keep only the domain part

    print(f"{Fore.GREEN}\n-------------------- Checking {subdomain} --------------------{Fore.RESET}")
    cname_records = get_cname(subdomain)
    if cname_records:
        for cname in cname_records:
            is_potentially_vulnerable = False
            for service in vulnerable_services:
                for pattern in service["cname_patterns"]:
                    if pattern in cname:
                        is_potentially_vulnerable = True
                        result = f"[+] {subdomain} has CNAME {cname} matching {pattern}"
                        print(Fore.YELLOW + result)
                        check_service_takeover(subdomain, cname, service, output_file)
                        break
                if is_potentially_vulnerable:
                    break
            if not is_potentially_vulnerable:
                result = f"[-] {subdomain} has CNAME {cname} but no matching vulnerable service"
                print(Fore.RED + result)
    else:
        result = f"[-] {subdomain} has no CNAME record"
        print(Fore.RED + result)
    print(f"{Fore.RED}-------------------- Finished checking {subdomain} --------------------{Fore.RESET}\n")

# Function to check if the service the subdomain points to shows signs of vulnerability
def check_service_takeover(subdomain, cname, service, output_file):
    try:
        for protocol in ['https://', 'http://']:
            # Ensure correct URL formatting
            subdomain_url = subdomain if subdomain.startswith(('http://', 'https://')) else protocol + subdomain
            print(f"Trying {subdomain_url}")
            response = requests.get(subdomain_url, timeout=10, verify=False)
            status_code = response.status_code
            title = get_page_title(response.content)
            response_text = response.text

            # Check for service-specific error messages indicating a takeover opportunity
            for error_msg in service["response_messages"]:
                if error_msg.lower() in response_text.lower():
                    result = f"[+] {subdomain} [{status_code}] [{title}] [Vulnerable to {service['service']}]"
                    print(Fore.GREEN + result)
                    with open(output_file, 'a') as f:
                        f.write(f"{subdomain} [Vulnerable to {service['service']}]\n")
                    return
            
            # If no vulnerabilities found, print a non-vulnerable result
            print(f"Checked {subdomain}: {status_code} - Not vulnerable")
        result = f"[-] {subdomain} [{status_code}] [{title}] [Not Vulnerable]"
        print(Fore.RED + result)
    except requests.exceptions.SSLError:
        result = f"[-] {subdomain} [SSL Error]"
        print(Fore.YELLOW + result)
    except requests.exceptions.Timeout:
        result = f"[-] {subdomain} [Timeout] [No response within 10 seconds]"
        print(Fore.YELLOW + result)
    except requests.exceptions.RequestException as e:
        result = f"[-] {subdomain} [Error] [Could not connect: {e}]"
        print(Fore.YELLOW + result)

# Main function to process the subdomain file and check for takeovers
def main(file_path, output_file):
    with open(output_file, 'w') as f:
        f.write("Vulnerable URLs:\n")
    
    try:
        with open(file_path, 'r') as file:
            domains = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(Fore.RED + f"[-] Error: File {file_path} not found.")
        return
    
    # Remove http:// and https:// from all domains in the list
    domains = [subdomain.split('://')[-1] for subdomain in domains]

    if domains:
        print(f"[+] Found {len(domains)} subdomains to check.")
        for subdomain in domains:
            check_subdomain_takeover(subdomain, output_file)
    else:
        print(Fore.RED + "[-] No domains found in the file.")

if __name__ == "__main__":
    print('''  
By M1S0 - https://x.com/UnknownMnz 
This tool is intended only for educational purposes and for testing in authorized environments. https://x.com/UnknownMnz and https://github.com/M1S0-0/M1S0 take no responsibility for the misuse of this code. Use it at your own risk. Do not attack a target you don't have permission to engage with. This tool uses the publicly released payloads and methods.
 ''')
    
    parser = argparse.ArgumentParser(description="Subdomain Takeover Checker")
    parser.add_argument("-f", "--file", help="Path to the file containing subdomains", required=True)
    args = parser.parse_args()

    output_file = "vulnerable_subdomain.txt"

    # List of vulnerable services with CNAME patterns and response messages
    vulnerable_services = [
        {
            "service": "AWS S3",
            "cname_patterns": ["s3.amazonaws.com", "amazonaws.com"],
            "response_messages": ["NoSuchBucket", "The specified bucket does not exist"]
        },
        {
            "service": "GitHub Pages",
            "cname_patterns": ["github.io"],
            "response_messages": ["There isn't a GitHub Pages site here."]
        },
        {
            "service": "Heroku",
            "cname_patterns": ["herokudns.com", "herokussl.com", "herokuapp.com"],
            "response_messages": ["No such app", "no-such-app"]
        },
        {
            "service": "Shopify",
            "cname_patterns": ["myshopify.com"],
            "response_messages": ["Sorry, this shop is currently unavailable."]
        },
        {
            "service": "Tumblr",
            "cname_patterns": ["domains.tumblr.com"],
            "response_messages": ["There's nothing here."]
        },
        {
            "service": "Azure",
            "cname_patterns": ["azurewebsites.net", "cloudapp.net"],
            "response_messages": ["Error 404 - Web app not found."]
        },
        {
            "service": "Bitbucket",
            "cname_patterns": ["bitbucket.io"],
            "response_messages": ["Repository not found"]
        },
        {
            "service": "Fastly",
            "cname_patterns": ["fastly.net", "fastlylb.net"],
            "response_messages": ["Fastly error: unknown domain", "Fastly error: unknown app"]
        },
        {
            "service": "Ghost",
            "cname_patterns": ["ghost.io"],
            "response_messages": ["The thing you were looking for is no longer here"]
        },
        {
            "service": "Pantheon",
            "cname_patterns": ["pantheon.io"],
            "response_messages": ["The gods are wise, but do not know of the site which you seek"]
        },
        {
            "service": "Surge.sh",
            "cname_patterns": ["surge.sh"],
            "response_messages": ["project not found"]
        },
        {
            "service": "Zendesk",
            "cname_patterns": ["zendesk.com"],
            "response_messages": ["Help Center Closed"]
        },
        {
            "service": "Amazon CloudFront",
            "cname_patterns": ["cloudfront.net"],
            "response_messages": ["Bad request", "ERROR: The request could not be satisfied"]
        },
        {
            "service": "Squarespace",
            "cname_patterns": ["squarespace.com"],
            "response_messages": ["No Such Account"]
        },
        {
            "service": "Unbounce",
            "cname_patterns": ["unbouncepages.com"],
            "response_messages": ["The requested URL was not found on this server"]
        },
        {
            "service": "WordPress.com",
            "cname_patterns": ["wordpress.com"],
            "response_messages": ["Do you want to register"]
        },
        {
            "service": "Intercom",
            "cname_patterns": ["custom.intercom.help"],
            "response_messages": ["This page is reserved for a Intercom customer"]
        },
        {
            "service": "Desk.com",
            "cname_patterns": ["desk.com"],
            "response_messages": ["Please try again or try Desk.com free for 14 days."]
        },
        {
            "service": "Cargo Collective",
            "cname_patterns": ["cargocollective.com"],
            "response_messages": ["404 Not Found"]
        },
        {
            "service": "Statuspage",
            "cname_patterns": ["statuspage.io"],
            "response_messages": ["Status page configured incorrectly"]
        },
        {
            "service": "SmartJobBoard",
            "cname_patterns": ["smartjobboard.com"],
            "response_messages": ["This job board website is either expired or its domain name is invalid"]
        },
        {
            "service": "Help Scout",
            "cname_patterns": ["helpscoutdocs.com"],
            "response_messages": ["No settings were found for this company:"]
        },
        {
            "service": "Tictail",
            "cname_patterns": ["tictail.com"],
            "response_messages": ["Starting your own Tictail store is easy"]
        },
        {
            "service": "Campaign Monitor",
            "cname_patterns": ["createsend.com"],
            "response_messages": ["Trying to access your account?"]
        },
        {
            "service": "Acquia",
            "cname_patterns": ["acquia-test.co"],
            "response_messages": ["Web Site Not Found"]
        },
        {
            "service": "Proposify",
            "cname_patterns": ["proposify.biz"],
            "response_messages": ["If you need immediate assistance, please contact Proposify Support"]
        },
        {
            "service": "Amazon Elastic Beanstalk",
            "cname_patterns": ["elasticbeanstalk.com"],
            "response_messages": ["404 Not Found"]
        },
        {
            "service": "Readme.io",
            "cname_patterns": ["readme.io"],
            "response_messages": ["Project doesnt exist... yet!"]
        },
    ]

    # Call the main function with provided file path
    main(args.file, output_file)
