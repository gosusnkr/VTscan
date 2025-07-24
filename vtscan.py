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
import ipaddress
import sys
import toml

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Use certifi CA bundle for HTTPS requests
ssl._create_default_https_context = ssl.create_default_context(cafile=certifi.where())

def load_api_key_from_vt_toml():
    home_dir = os.path.expanduser('~')
    vt_toml_path = os.path.join(home_dir, '.vt.toml')

    if not os.path.exists(vt_toml_path):
        print(f"Error: .vt.toml file not found at {vt_toml_path}")
        return None

    try:
        config = toml.load(vt_toml_path)
        apikey = config.get('apikey')
        if apikey:
            return apikey.strip('"').strip("'")  # remove quotes if any
        else:
            print("Error: 'apikey' not found in .vt.toml file")
            return None
    except Exception as e:
        print(f"Error reading .vt.toml: {e}")
        return None

# Load API key from .vt.toml file
api_key = load_api_key_from_vt_toml()
if not api_key:
    print("VirusTotal API key not found. Please check your .vt.toml file.")
    sys.exit(1)

def scan(input_type, value, delay):
    if input_type == 'domain':
        endpoint = 'domains'
        first_column = 'Domain'
    elif input_type == 'ip':
        endpoint = 'ip_addresses'
        first_column = 'IP Address'
    elif input_type == 'url':
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        return scan_url(url, delay)
    elif input_type == 'hash':
        endpoint = 'files'
        first_column = 'File Hash'
    else:
        print("Invalid input type. Supported types are 'domain', 'ip', 'url', and 'hash'.")
        return None

    url = f'https://www.virustotal.com/api/v3/{endpoint}/{value}'

    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

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
        print(f"Error {response.status_code}: {response.text}")
        return None

def scan_url(url, delay):
    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

    if response.status_code == 200:
        data = response.json()['data']
        hash_value = data['id']
        scan_results = data['attributes']['last_analysis_results']

        detection_status = {
            engine: result.get("category")
            for engine, result in scan_results.items()
        }

        return {'URL': url, 'Hash Value': hash_value, **detection_status}
    else:
        print(f"Error {response.status_code}: {response.text}")
        return None

def scan_single(value, delay):
    print(f"Scanning single: {value}")
    input_type = determine_input_type(value)
    if input_type:
        result = scan(input_type, value, delay)
        if result:
            print_result(result)
            print(f"Overall Status: {determine_overall_status(result)}")
        else:
            print("No result returned for the input.")
    else:
        print("Invalid input.")

def scan_list(file_path, output_file=None, delay=0):
    print(f"Scanning list: {file_path}")
    results = []
    all_keys = set()

    try:
        with open(file_path, 'r') as file:
            inputs = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return

    for entry in inputs:
        input_type = determine_input_type(entry)
        if not input_type:
            print(f"Invalid input: {entry}")
            continue

        print(f"Scanning: {entry}")
        result = scan(input_type, entry, delay)
        if result is None:
            print(f"No result found for input: {entry}")
            continue

        # Add 'Input' as the original user input (URL/domain/hash)
        result['Input'] = entry
        result['Overall Status'] = determine_overall_status(result)
        results.append(result)

        all_keys.update(result.keys())
        time.sleep(delay)

    # Enforce 'Overall Status' first, then 'Input', then the rest sorted
    fixed_columns = ['Overall Status', 'Input']
    dynamic_columns = sorted(k for k in all_keys if k not in fixed_columns)
    fieldnames = fixed_columns + dynamic_columns

    if output_file is None:
        output_file = 'report.txt'
    else:
        output_file = os.path.join(os.getcwd(), output_file)

    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    _, file_ext = os.path.splitext(output_file)
    file_ext = file_ext.lower()

    if file_ext == '.json':
        with open(output_file, 'w', encoding='utf-8') as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Report saved as {output_file}")
    elif file_ext == '.csv':
        with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow({field: row.get(field, '') for field in fieldnames})
        print(f"Report saved as {output_file}")
    else:
        # Plain text output
        with open(output_file, 'w', encoding='utf-8') as txt_file:
            for result in results:
                for k, v in result.items():
                    txt_file.write(f"{k}: {v}\n")
                txt_file.write("\n")
        print(f"Report saved as {output_file}")

def determine_overall_status(result):
    malicious_statuses = {"malicious", "suspicious"}
    detection_count = 0

    for engine, status in result.items():
        if engine.lower() in ("input", "overall status", "hash value"):
            continue
        if status is None or status == '':
            continue
        if status.lower() in malicious_statuses:
            detection_count += 1

    if detection_count > 0:
        return f"Malicious ({detection_count} detections)"
    else:
        return "Clean"

def determine_input_type(value):
    domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    url_pattern = r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/?'
    md5_pattern = r'^[a-fA-F0-9]{32}$'
    sha1_pattern = r'^[a-fA-F0-9]{40}$'
    sha256_pattern = r'^[a-fA-F0-9]{64}$'

    try:
        ipaddress.ip_address(value)
        return 'ip'
    except ValueError:
        pass

    if re.match(domain_pattern, value):
        return 'domain'
    elif re.match(url_pattern, value):
        return 'url'
    elif re.match(md5_pattern, value):
        return 'hash'
    elif re.match(sha1_pattern, value):
        return 'hash'
    elif re.match(sha256_pattern, value):
        return 'hash'
    else:
        return None

def print_result(result):
    if result:
        print("Scan Results:")
        for engine, status in result.items():
            if engine != 'Hash Value':
                print(f"{engine}: {status}")
    else:
        print("No results found.")

parser = argparse.ArgumentParser(
    description='VirusTotal Scan',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''Example Scan Commands:
  python vtscan.py -s google.com        # Single scan
  python vtscan.py -l test.txt           # List scan
  python vtscan.py -l test.txt -o json   # List scan with JSON output
  python vtscan.py -l test.txt -o csv    # List scan with CSV output
'''
)

parser.add_argument('-s', '--single', type=str, help='Perform a single scan')
parser.add_argument('-l', '--list', type=str, help='Scan a list of inputs from a file')
parser.add_argument('-o', '--output', type=str, help='Output file name with format (JSON or CSV)')
parser.add_argument('-t', '--delay', type=int, default=0, help='Delay between scans (in seconds)')

if __name__ == "__main__":
    args = parser.parse_args()

    if args.single:
        scan_single(args.single, args.delay)
    elif args.list:
        scan_list(args.list, args.output, args.delay)
    else:
        parser.print_help()
