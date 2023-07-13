import argparse
import requests
import json
import csv
import time
import urllib3
import ssl
import certifi
import base64
import re
import os

# Set the SSL certificate bundle path
ssl._create_default_https_context = ssl._create_unverified_context
ssl._create_default_https_context = ssl.create_default_context(cafile=certifi.where())

# Disable SSL certificate verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set the path to the CA bundle file
CA_CERT_PATH = r'D:\My ALDAR Documents\sgosu\Documents\cacert.pem'  # Update with the correct path to the downloaded file

def scan(input_type, value, delay):
    # Provide your VirusTotal API key
    api_key = '8699ba10ae9686d602e9f945cf9687b64a28208b50de9f1e78970c31645034bb'

    # Set the appropriate API endpoint based on the input type
    if input_type == 'domain':
        endpoint = 'domains'
        first_column = 'Domain'
    elif input_type == 'ip':
        endpoint = 'ip_addresses'
        first_column = 'IP Address'
    elif input_type == 'url':
        # Generate URL identifier from the value
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        return scan_url(url, 'URL', delay)
    elif input_type == 'hash':
        endpoint = 'files'
        first_column = 'File Hash'
    else:
        print("Invalid input type. Supported types are 'domain', 'ip', 'url', and 'hash'.")
        return

    # Create the URL for scanning
    url = f'https://www.virustotal.com/api/v3/{endpoint}/{value}'

    # Set the request headers with the API key
    headers = {
        'x-apikey': api_key
    }

    # Send the GET request to scan the input
    response = requests.get(url, headers=headers, verify=False)

    # Check the response status
    if response.status_code == 200:
        data = response.json()['data']
        hash_value = data['id']
        scan_results = data['attributes']['last_analysis_results']

        detection_status = {
            engine: result.get("category")
            for engine, result in scan_results.items()
        }

        return {first_column: value, 'Hash Value': hash_value, **detection_status}
    else:
        print("An error occurred during the scan.")

def scan_url(url, input_type, delay):
    # Provide your VirusTotal API key
    api_key = '8699ba10ae9686d602e9f945cf9687b64a28208b50de9f1e78970c31645034bb'

    # Set the request headers with the API key
    headers = {
        'x-apikey': api_key
    }

    # Send the GET request to scan the URL
    response = requests.get(url, headers=headers, verify=False)

    # Check the response status
    if response.status_code == 200:
        data = response.json()['data']
        hash_value = data['id']
        scan_results = data['attributes']['last_analysis_results']

        detection_status = {
            engine: result.get("category")
            for engine, result in scan_results.items()
        }

        return {input_type: url, 'Hash Value': hash_value, **detection_status}
    else:
        print("An error occurred during the scan.")

def scan_single(value, delay):
    print("Scanning single: {}".format(value))
    input_type = determine_input_type(value)
    if input_type:
        result = scan(input_type, value, delay)
        print_result(result)
        print("Overall Status: {}".format(determine_overall_status(result)))  # Print the overall status
    else:
        print("Invalid input.")

def scan_list(file_path, output_file=None, delay=0):
    print(f"Scanning list: {file_path}")
    results = []
    fieldnames = ['Overall Status']  # Initialize fieldnames with 'Overall Status'
    with open(file_path, 'r') as file:
        for line in file:
            value = line.strip()
            input_type = determine_input_type(value)
            if input_type:
                result = scan(input_type, value, delay)
                result['Overall Status'] = determine_overall_status(result)  # Add 'Overall Status' to the result dictionary

                results.append(result)

                # Extend fieldnames with the additional engines found in the result
                fieldnames.extend(engine for engine in result.keys() if engine != 'Hash Value' and engine not in fieldnames)

                # Delay for the specified duration
                time.sleep(delay)
            else:
                print(f"Invalid input: {value}")

    if output_file is None:
        output_file = 'report.txt'
    else:
        output_file = os.path.join(os.getcwd(), output_file)

    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)

    _, file_ext = os.path.splitext(output_file)
    if file_ext == '.json':
        with open(output_file, 'w') as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Report saved as {output_file}")
    elif file_ext == '.csv':
        with open(output_file, 'w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                row = {field: result.get(field, '') for field in fieldnames}  # Create a row dictionary with default values
                writer.writerow(row)
        print(f"Report saved as {output_file}")
    else:
        print(f"Invalid output file format: {file_ext}. Report saved as {output_file} in plain text format.")

def determine_overall_status(result):
    # Determine the overall status based on the individual scan results
    for status in result.values():
        if status != 'clean':
            return 'Malicious'
    return 'Clean'

def determine_input_type(value):
    # Regex patterns for input types
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    url_pattern = r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/?'

    if re.match(domain_pattern, value):
        return 'domain'
    elif re.match(ip_pattern, value):
        return 'ip'
    elif re.match(url_pattern, value):
        return 'url'
    else:
        return 'hash'

def print_result(result):
    if result:
        print("Scan Results:")
        for engine, status in result.items():
            if engine != 'Hash Value':
                print("{}: {}".format(engine, status))
    else:
        print("No results found.")

# Create the command-line argument parser
parser = argparse.ArgumentParser(description='VirusTotal Scan')

# Define example scan commands for help section
example_commands = '''Example Scan Commands:
  python vtscan.py -s google.com        # Single scan
  python vtscan.py -l test.txt           # List scan
  python vtscan.py -l test.txt -o json   # List scan with JSON output
  python vtscan.py -l test.txt -o csv    # List scan with CSV output
'''

parser.epilog = example_commands  # Add example commands to the help section
parser.formatter_class = argparse.RawDescriptionHelpFormatter  # Preserve line breaks in help message

parser.add_argument('-s', '--single', type=str, help='Perform a single scan')
parser.add_argument('-l', '--list', type=str, help='Scan a list of inputs from a file')
parser.add_argument('-o', '--output', type=str, help='Output file name with format (JSON or CSV)')
parser.add_argument('-t', '--delay', type=int, default=0, help='Delay between scans (in seconds)')

# Parse the command-line arguments
args = parser.parse_args()

# Perform the scan based on the provided options
if args.single:
    scan_single(args.single, args.delay)
elif args.list:
    scan_list(args.list, args.output, args.delay)
else:
    parser.print_help()
