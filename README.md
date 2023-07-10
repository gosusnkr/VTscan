# VTscan
To check whether a list of IOC (Indicators of Compromise) is already included in all threat indicators.

Before running the script, there are a few prerequisites that you need to have in place:

1. Python: Make sure you have Python installed on your machine. You can download and install Python from the official Python website (https://www.python.org) based on your operating system.

2. vt Python Library: Install the `vt` Python library, which is used for interacting with the VirusTotal API. You can install it using the following command:

   ```
   pip install vt
   ```

3. VirusTotal API Key: Obtain an API key from VirusTotal. You can sign up for a free account at the VirusTotal website (https://www.virustotal.com) and obtain your API key from the API section of your account settings. Replace `<YOUR_API_KEY>` in the script with your actual API key.

Once you have fulfilled these prerequisites, you should be able to run the script and perform VirusTotal scans using the provided commands.

Please note that some features or functionalities may require additional permissions or paid subscription plans on VirusTotal. Make sure you have the necessary access or permissions for the specific operations you intend to perform.

```
python vtscan.py 
usage: vtscan.py [-h] [-d] [-i] [-u] [-f] [-s INPUT] [-l FILE_PATH] [-o {json,csv}]

VirusTotal Scan

options:
  -h, --help            show this help message and exit
  -d, --domain          Scan a domain
  -i, --ip              Scan an IP address
  -u, --url             Scan a URL
  -f, --file            Scan a file hash
  -s INPUT, --single INPUT
                        Scan a single input
  -l FILE_PATH, --list FILE_PATH
                        Scan a list of inputs from a file
  -o {json,csv}, --output {json,csv}
                        Generate a report in JSON or CSV format

Example Scan Commands:
  python vtscan.py -d -s google.com                                                        # Single domain scan
  python vtscan.py -i -s 171.25.0.45                                                       # Single IP scan
  python vtscan.py -u -s www.google.com/search                                             # Single URL scan
  python vtscan.py -f -s 543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91  # Single file hash scan
  python vtscan.py -d -l test.txt                                                          # List of domains scan
  python vtscan.py -i -l test.txt                                                          # List of IPs scan
  python vtscan.py -u -l test.txt                                                          # List of URLs scan
  python vtscan.py -f -l test.txt                                                          # List of file hashes scan
  python vtscan.py -f -l test.txt -o json                                                  # List of file hashes scan with JSON output
  python vtscan.py -f -l test.txt -o csv                                                   # List of file hashes scan with CSV output
```
