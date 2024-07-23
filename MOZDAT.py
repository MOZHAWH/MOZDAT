import subprocess
import sys
import os
import argparse
import json
import logging
from tqdm import tqdm
import colorama
from colorama import Fore, Style
import whois

colorama.init(autoreset=True)

logging.basicConfig(filename='domain_check.log', level=logging.INFO, 
                    format='%(asctime)s:%(levelname)s:%(message)s')

def print_banner():
    text = f"""
{Fore.GREEN}
         __  __  ___ _________    _  _____ 
        |  \/  |/ _ \__  /  _ \  / \|_   _|
        | |\/| | | | |/ /| | | |/ _ \ | |  
        | |  | | |_| / /_| |_| / ___ \| |  
        |_|  |_|\___/____|____/_/   \_\_|  
                                   

        {Fore.CYAN}Telegram Channel: @MOZHAWH | Version: 2.0  
            
    """
    print(text)

def check_cname_for_domains(filename, output_filename):
    with open(filename, 'r') as f:
        domains = f.read().splitlines()

    results = []

    for domain in tqdm(domains, desc="Progress", unit="domain"):
        domain = domain.replace("https://", "").replace("http://", "").strip("/")  
        result = {"domain": domain}

        
        try:
            cname_result = subprocess.run(["dig", "+short", "CNAME", domain], capture_output=True, text=True, timeout=30, check=True)
            cname_output = cname_result.stdout.strip()
            if cname_output:
                result["cname"] = cname_output
                print(f"{Fore.GREEN}CNAME for {domain}: {Style.RESET_ALL}{cname_output}")
            else:
                result["cname"] = "No CNAME record found"
                print(f"{Fore.YELLOW}No CNAME record found for {domain}")
        except subprocess.CalledProcessError as e:
            result["cname"] = f"Error: {e}"
            print(f"{Fore.RED}Error checking CNAME for {domain}: {Style.RESET_ALL}{e}")
        except subprocess.TimeoutExpired:
            result["cname"] = "Timeout"
            print(f"{Fore.RED}Timeout checking CNAME for {domain}{Style.RESET_ALL}")
        except Exception as e:
            result["cname"] = f"Unexpected error: {e}"
            print(f"{Fore.RED}Unexpected error checking CNAME for {domain}: {Style.RESET_ALL}{e}")

        
        try:
            ping_result = subprocess.run(["ping", "-c", "4", domain], capture_output=True, text=True, timeout=30)
            if ping_result.returncode == 0:
                result["ping"] = "Online"
                print(f"{Fore.GREEN}{domain} is online")
            else:
                result["ping"] = "Offline"
                print(f"{Fore.RED}{domain} is offline")
        except subprocess.CalledProcessError as e:
            result["ping"] = f"Error: {e}"
            print(f"{Fore.RED}Error pinging {domain}: {Style.RESET_ALL}{e}")
        except subprocess.TimeoutExpired:
            result["ping"] = "Timeout"
            print(f"{Fore.RED}Timeout pinging {domain}{Style.RESET_ALL}")
        except Exception as e:
            result["ping"] = f"Unexpected error: {e}"
            print(f"{Fore.RED}Unexpected error pinging {domain}: {Style.RESET_ALL}{e}")

        
        try:
            whois_info = whois.whois(domain)
            result["whois"] = {
                "expiration_date": str(whois_info.expiration_date),
                "registrar": whois_info.registrar,
                "name": whois_info.name,
                "organization": whois_info.org,
                "emails": whois_info.emails
            }
            print(f"{Fore.BLUE}WHOIS for {domain}: {Style.RESET_ALL}{result['whois']}")
        except Exception as e:
            result["whois"] = f"Unexpected error: {e}"
            print(f"{Fore.RED}Unexpected error retrieving WHOIS for {domain}: {Style.RESET_ALL}{e}")

        results.append(result)
        logging.info(result)

    if output_filename:
        with open(output_filename, 'w') as out_file:
            json.dump(results, out_file, indent=4)

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Check CNAME records, ping domains, and get WHOIS information.")
    parser.add_argument('filename', type=str, help="Path to the file containing domains (e.g., domains.txt)")
    parser.add_argument('--output', type=str, help="Path to the output file to save results (e.g., results.json)", default=None)
    
    args = parser.parse_args()

    if not os.path.isfile(args.filename):
        print(f"{Fore.RED}File not found: {args.filename}{Style.RESET_ALL}")
        sys.exit(1)

    check_cname_for_domains(args.filename, args.output)

if __name__ == "__main__":
    main()
