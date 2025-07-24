# VTscan
To check whether a list of IOC (Indicators of Compromise) is already included in all threat indicators.

Before running the script, there are a few prerequisites that you need to have in place:

1. Python: Make sure you have Python installed on your machine. You can download and install Python from the official Python website (https://www.python.org) based on your operating system.
2. VirusTotal API Key: Obtain an API key from VirusTotal. You can sign up for a free account at the VirusTotal website (https://www.virustotal.com) and obtain your API key from the API section of your account settings. Create a file with name ".vt.toml" in current user home directory and then add apikey="VIRUS_TOTAL_API_KEY_HERE"
3. Do the below
```
   git clone https://github.com/gosusnkr/VTscan.git
   cd VTscan
   pip install -r requirements.txt
```
If you get an SSL-related issue while installing dependencies, use the command below.
```
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```
Once you have fulfilled these prerequisites, you should be able to run the script and perform VirusTotal scans using the provided commands.

Please note that some features or functionalities may require additional permissions or paid subscription plans on VirusTotal. Make sure you have the necessary access or permissions for the specific operations you intend to perform.

```
python vtscan.py 
usage: vtscan.py [-h] [-d] [-i] [-u] [-f] [-s INPUT] [-l FILE_PATH] [-o {json,csv}]

VirusTotal Scan

options:
  -h, --help                           show this help message and exit
  -s INPUT, --single INPUT             Scan a single input                                       
  -l FILE_PATH, --list FILE_PATH       Scan a list of inputs from a file
  -t DELAY, --delay DELAY              Time delay in seconds between each scan, the default value is 0, meaning no delay.                                                       
  -o {json,csv}, --output {json,csv}   Generate a report in JSON or CSV format                                    

Example Scan Commands:
  python vtscan.py -s google.com                                                        # Single domain scan
  python vtscan.py -s 171.25.0.45                                                       # Single IP scan
  python vtscan.py -s www.google.com/search                                             # Single URL scan
  python vtscan.py -s 543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91  # Single file hash scan
  python vtscan.py -l input.txt -o output.json                                          # List of IOCs scan with JSON output getting saved output.json filename.
  python vtscan.py -l input.txt -o output.csv                                           # List of IOCs scan with CSV output getting saved output.csv filename.
  python vtscan.py -l input.txt -t 30 -o output.csv                                     # List of IOCs scan with 30 seconds time delay between each scan with JSON output getting saved output.json filename.
  python vtscan.py -l input.txt -t 30 -o output.csv                                     # List of IOCs scan with 30 seconds time delay between each scan with CSV output getting saved output.csv
```
# Save all file hashes into a single file and give them as input, the same for URLs, DOMAINs and IPs.
