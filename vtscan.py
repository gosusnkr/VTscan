import argparse
import requests
import json
import csv

def scan(input_type, value):
    # Provide your VirusTotal API key
    api_key = '<YOUR_API_KEY>'  # Replace <YOUR_API_KEY> with your actual API key

    # Set the appropriate API endpoint based on the input type
    if input_type == 'domain':
        endpoint = 'domains'
    elif input_type == 'ip':
        endpoint = 'ip_addresses'
    elif input_type == 'url':
        endpoint = 'urls'
    elif input_type == 'hash':
        endpoint = 'files'
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
    response = requests.get(url, headers=headers)

    # Check the response status
    if response.status_code == 200:
        data = response.json()['data']
        hash_value = data['id']
        scan_results = data['attributes']['last_analysis_results']

        detection_status = {
            engine: result.get("category")
            for engine, result in scan_results.items()
        }

        return {'Hash Value': hash_value, **detection_status}
    else:
        print("An error occurred during the scan.")

def scan_single(input_type, value):
    print("Scanning single {}: {}".format(input_type, value))
    result = scan(input_type, value)
    print_result(result)

def scan_list(input_type, file_path, output_format=None):
    print("Scanning list of {}: {}".format(input_type, file_path))
    results = []
    fieldnames = ['Hash Value']  # Initialize fieldnames with 'Hash Value' as the first column
    with open(file_path, 'r') as file:
        for line in file:
            value = line.strip()
            result = scan(input_type, value)
            results.append(result)

            # Extend fieldnames with the additional engines found in the result
            fieldnames.extend(engine for engine in result.keys() if engine != 'Hash Value' and engine not in fieldnames)

    if output_format == 'json':
        output_file = f'report_{input_type}.json'
        with open(output_file, 'w') as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Report saved as {output_file}")
    elif output_format == 'csv':
        output_file = f'report_{input_type}.csv'
        with open(output_file, 'w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                row = {field: result.get(field, '') for field in fieldnames}  # Create a row dictionary with default values
                writer.writerow(row)
        print(f"Report saved as {output_file}")

def print_result(result):
    if result:
        print("Scan Results:")
        for engine, status in result.items():
            if engine == 'Hash Value':
                print("Hash Value: {}".format(status))
            else:
                print("{}: {}".format(engine, status))
    else:
        print("No results found.")

# Create the command-line argument parser
parser = argparse.ArgumentParser(description='VirusTotal Scan')

# Define example scan commands for help section
example_commands = '''Example Scan Commands:
  python vttest.py -d -s google.com        # Single domain scan
  python vttest.py -i -s 171.25.0.45       # Single IP scan
  python vttest.py -u -s google.com/search # Single URL scan
  python vttest.py -f -s 543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91 \\
                                           # Single file hash scan
  python vttest.py -d -l test.txt           # List of domains scan
  python vttest.py -i -l test.txt           # List of IPs scan
  python vttest.py -u -l test.txt           # List of URLs scan
  python vttest.py -f -l test.txt           # List of file hashes scan
  python vttest.py -f -l test.txt -o json   # List of file hashes scan with JSON output
  python vttest.py -f -l test.txt -o csv    # List of file hashes scan with CSV output
'''
parser.epilog = example_commands  # Add example commands to the help section
parser.formatter_class = argparse.RawDescriptionHelpFormatter  # Preserve line breaks in help message

parser.add_argument('-d', '--domain', action='store_true', help='Scan a domain')
parser.add_argument('-i', '--ip', action='store_true', help='Scan an IP address')
parser.add_argument('-u', '--url', action='store_true', help='Scan a URL')
parser.add_argument('-f', '--file', action='store_true', help='Scan a file hash')
parser.add_argument('-s', '--single', metavar='INPUT', help='Scan a single input')
parser.add_argument('-l', '--list', metavar='FILE_PATH', help='Scan a listof inputs from a file')
parser.add_argument('-o', '--output', choices=['json', 'csv'], help='Generate a report in JSON or CSV format')

# Parse the command-line arguments
args = parser.parse_args()

# Check the provided options and arguments
if args.single:
    if args.domain:
        scan_single('domain', args.single)
    elif args.ip:
        scan_single('ip', args.single)
    elif args.url:
        scan_single('url', args.single)
    elif args.file:
        scan_single('hash', args.single)
    else:
        print("No input type specified. Use either -d, -i, -u, or -f for single input scanning.")
elif args.list:
    if args.domain:
        scan_list('domain', args.list, args.output)
    elif args.ip:
        scan_list('ip', args.list, args.output)
    elif args.url:
        scan_list('url', args.list, args.output)
    elif args.file:
        scan_list('hash', args.list, args.output)
    else:
        print("No input type specified. Use either -d, -i, -u, or -f for list input scanning.")
else:
    parser.print_help()
