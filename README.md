The "MOZ Domain Analysis Tool (MOZDOT)" script is a comprehensive and intelligent tool for checking and analyzing domains. This script includes the following features:

CNAME Records Check:

Uses the dig command to check the CNAME records of domains and displays the result.
Ping Domains:

Uses the ping command to check the online status of domains.
WHOIS Information Retrieval:

Uses the whois library to extract information such as domain expiration date, registrar, registrant name, organization, and related emails.
Save Results in JSON Format:

All results are saved in a JSON file, making it more readable and organized.
Error Handling and Logging:

All errors are appropriately managed, and results are logged into a log file.

Usage:
pip install tqdm colorama python-whois

python mozdi.py domains.txt --output results.json
