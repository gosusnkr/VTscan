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

# Output examples
For single hash
```
python vtscan.py -f -s 759b227259adf08c2ebe250c823963b14a98dd1f17065da47d7ccb7c9c7d5b60
Scanning single hash: 759b227259adf08c2ebe250c823963b14a98dd1f17065da47d7ccb7c9c7d5b60
Scan Results:
Hash Value: 759b227259adf08c2ebe250c823963b14a98dd1f17065da47d7ccb7c9c7d5b60
Bkav: undetected
Lionic: malicious
tehtris: type-unsupported
ClamAV: undetected
FireEye: malicious
CAT-QuickHeal: malicious
McAfee: malicious
Malwarebytes: undetected
Zillya: undetected
Sangfor: undetected
K7AntiVirus: undetected
Alibaba: type-unsupported
K7GW: undetected
Trustlook: type-unsupported
BitDefenderTheta: undetected
VirIT: undetected
Cyren: malicious
SymantecMobileInsight: type-unsupported
Symantec: malicious
Elastic: type-unsupported
ESET-NOD32: malicious
APEX: type-unsupported
TrendMicro-HouseCall: undetected
Avast: malicious
Cynet: malicious
Kaspersky: malicious
BitDefender: malicious
NANO-Antivirus: undetected
SUPERAntiSpyware: undetected
MicroWorld-eScan: malicious
Tencent: malicious
TACHYON: undetected
Emsisoft: malicious
Baidu: undetected
F-Secure: malicious
DrWeb: undetected
VIPRE: malicious
TrendMicro: undetected
McAfee-GW-Edition: malicious
SentinelOne: type-unsupported
Trapmine: type-unsupported
CMC: undetected
Sophos: malicious
Paloalto: type-unsupported
GData: malicious
Jiangmin: undetected
Webroot: type-unsupported
Avira: malicious
Antiy-AVL: malicious
Gridinsoft: undetected
Xcitium: undetected
Arcabit: malicious
ViRobot: malicious
ZoneAlarm: malicious
Avast-Mobile: type-unsupported
Microsoft: malicious
Google: malicious
BitDefenderFalx: type-unsupported
AhnLab-V3: malicious
Acronis: undetected
VBA32: undetected
ALYac: malicious
MAX: malicious
DeepInstinct: type-unsupported
Cylance: type-unsupported
Zoner: undetected
Rising: malicious
Yandex: undetected
Ikarus: malicious
MaxSecure: undetected
Fortinet: undetected
AVG: malicious
Cybereason: type-unsupported
Panda: undetected
CrowdStrike: type-unsupported
```
For list in json format
```
[
    {
        "Hash Value": "759b227259adf08c2ebe250c823963b14a98dd1f17065da47d7ccb7c9c7d5b60",
        "Bkav": "undetected",
        "Lionic": "malicious",
        "tehtris": "type-unsupported",
        "ClamAV": "undetected",
        "FireEye": "malicious",
        "CAT-QuickHeal": "malicious",
        "McAfee": "malicious",
        "Malwarebytes": "undetected",
        "Zillya": "undetected",
        "Sangfor": "undetected",
        "K7AntiVirus": "undetected",
        "Alibaba": "type-unsupported",
        "K7GW": "undetected",
        "Trustlook": "type-unsupported",
        "BitDefenderTheta": "undetected",
        "VirIT": "undetected",
        "Cyren": "malicious",
        "SymantecMobileInsight": "type-unsupported",
        "Symantec": "malicious",
        "Elastic": "type-unsupported",
        "ESET-NOD32": "malicious",
        "APEX": "type-unsupported",
        "TrendMicro-HouseCall": "undetected",
        "Avast": "malicious",
        "Cynet": "malicious",
        "Kaspersky": "malicious",
        "BitDefender": "malicious",
        "NANO-Antivirus": "undetected",
        "SUPERAntiSpyware": "undetected",
        "MicroWorld-eScan": "malicious",
        "Tencent": "malicious",
        "TACHYON": "undetected",
        "Emsisoft": "malicious",
        "Baidu": "undetected",
        "F-Secure": "malicious",
        "DrWeb": "undetected",
        "VIPRE": "malicious",
        "TrendMicro": "undetected",
        "McAfee-GW-Edition": "malicious",
        "SentinelOne": "type-unsupported",
        "Trapmine": "type-unsupported",
        "CMC": "undetected",
        "Sophos": "malicious",
        "Paloalto": "type-unsupported",
        "GData": "malicious",
        "Jiangmin": "undetected",
        "Webroot": "type-unsupported",
        "Avira": "malicious",
        "Antiy-AVL": "malicious",
        "Gridinsoft": "undetected",
        "Xcitium": "undetected",
        "Arcabit": "malicious",
        "ViRobot": "malicious",
        "ZoneAlarm": "malicious",
        "Avast-Mobile": "type-unsupported",
        "Microsoft": "malicious",
        "Google": "malicious",
        "BitDefenderFalx": "type-unsupported",
        "AhnLab-V3": "malicious",
        "Acronis": "undetected",
        "VBA32": "undetected",
        "ALYac": "malicious",
        "MAX": "malicious",
        "DeepInstinct": "type-unsupported",
        "Cylance": "type-unsupported",
        "Zoner": "undetected",
        "Rising": "malicious",
        "Yandex": "undetected",
        "Ikarus": "malicious",
        "MaxSecure": "undetected",
        "Fortinet": "undetected",
        "AVG": "malicious",
        "Cybereason": "type-unsupported",
        "Panda": "undetected",
        "CrowdStrike": "type-unsupported"
    },
    {
        "Hash Value": "543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91",
        "Bkav": "undetected",
        "Lionic": "undetected",
        "Elastic": "undetected",
        "DrWeb": "undetected",
        "Cynet": "undetected",
        "CMC": "undetected",
        "CAT-QuickHeal": "undetected",
        "ALYac": "undetected",
        "Cylance": "undetected",
        "VIPRE": "undetected",
        "Sangfor": "undetected",
        "CrowdStrike": "undetected",
        "Alibaba": "undetected",
        "K7GW": "undetected",
        "K7AntiVirus": "undetected",
        "BitDefenderTheta": "undetected",
        "VirIT": "undetected",
        "Cyren": "malicious",
        "SymantecMobileInsight": "type-unsupported",
        "Symantec": "undetected",
        "tehtris": "undetected",
        "ESET-NOD32": "undetected",
        "APEX": "undetected",
        "Paloalto": "undetected",
        "ClamAV": "undetected",
        "Kaspersky": "undetected",
        "BitDefender": "undetected",
        "NANO-Antivirus": "undetected",
        "ViRobot": "undetected",
        "MicroWorld-eScan": "undetected",
        "Avast": "undetected",
        "Rising": "undetected",
        "Trustlook": "type-unsupported",
        "TACHYON": "undetected",
        "Emsisoft": "undetected",
        "F-Secure": "undetected",
        "Baidu": "undetected",
        "Zillya": "undetected",
        "TrendMicro": "undetected",
        "McAfee-GW-Edition": "malicious",
        "Trapmine": "undetected",
        "FireEye": "undetected",
        "Sophos": "undetected",
        "Ikarus": "malicious",
        "Avast-Mobile": "type-unsupported",
        "Jiangmin": "undetected",
        "Webroot": "malicious",
        "Avira": "undetected",
        "Antiy-AVL": "malicious",
        "Microsoft": "undetected",
        "Gridinsoft": "undetected",
        "Xcitium": "undetected",
        "Arcabit": "undetected",
        "SUPERAntiSpyware": "undetected",
        "ZoneAlarm": "undetected",
        "GData": "undetected",
        "Google": "malicious",
        "BitDefenderFalx": "type-unsupported",
        "AhnLab-V3": "undetected",
        "Acronis": "undetected",
        "McAfee": "malicious",
        "MAX": "undetected",
        "VBA32": "undetected",
        "Malwarebytes": "malicious",
        "Panda": "undetected",
        "Zoner": "undetected",
        "TrendMicro-HouseCall": "undetected",
        "Tencent": "undetected",
        "Yandex": "undetected",
        "SentinelOne": "undetected",
        "MaxSecure": "undetected",
        "Fortinet": "malicious",
        "AVG": "undetected",
        "Cybereason": "timeout",
        "DeepInstinct": "malicious"
    }
]
```
For list in csv format
```
Hash Value,Bkav,Lionic,tehtris,ClamAV,FireEye,CAT-QuickHeal,McAfee,Malwarebytes,Zillya,Sangfor,K7AntiVirus,Alibaba,K7GW,Trustlook,BitDefenderTheta,VirIT,Cyren,SymantecMobileInsight,Symantec,Elastic,ESET-NOD32,APEX,TrendMicro-HouseCall,Avast,Cynet,Kaspersky,BitDefender,NANO-Antivirus,SUPERAntiSpyware,MicroWorld-eScan,Tencent,TACHYON,Emsisoft,Baidu,F-Secure,DrWeb,VIPRE,TrendMicro,McAfee-GW-Edition,SentinelOne,Trapmine,CMC,Sophos,Paloalto,GData,Jiangmin,Webroot,Avira,Antiy-AVL,Gridinsoft,Xcitium,Arcabit,ViRobot,ZoneAlarm,Avast-Mobile,Microsoft,Google,BitDefenderFalx,AhnLab-V3,Acronis,VBA32,ALYac,MAX,DeepInstinct,Cylance,Zoner,Rising,Yandex,Ikarus,MaxSecure,Fortinet,AVG,Cybereason,Panda,CrowdStrike
759b227259adf08c2ebe250c823963b14a98dd1f17065da47d7ccb7c9c7d5b60,undetected,malicious,type-unsupported,undetected,malicious,malicious,malicious,undetected,undetected,undetected,undetected,type-unsupported,undetected,type-unsupported,undetected,undetected,malicious,type-unsupported,malicious,type-unsupported,malicious,type-unsupported,undetected,malicious,malicious,malicious,malicious,undetected,undetected,malicious,malicious,undetected,malicious,undetected,malicious,undetected,malicious,undetected,malicious,type-unsupported,type-unsupported,undetected,malicious,type-unsupported,malicious,undetected,type-unsupported,malicious,malicious,undetected,undetected,malicious,malicious,malicious,type-unsupported,malicious,malicious,type-unsupported,malicious,undetected,undetected,malicious,malicious,type-unsupported,type-unsupported,undetected,malicious,undetected,malicious,undetected,undetected,malicious,type-unsupported,undetected,type-unsupported
543991ca8d1c65113dff039b85ae3f9a87f503daec30f46929fd454bc57e5a91,undetected,undetected,undetected,undetected,undetected,undetected,malicious,malicious,undetected,undetected,undetected,undetected,undetected,type-unsupported,undetected,undetected,malicious,type-unsupported,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,undetected,malicious,undetected,undetected,undetected,undetected,undetected,undetected,undetected,malicious,undetected,malicious,undetected,undetected,undetected,undetected,undetected,type-unsupported,undetected,malicious,type-unsupported,undetected,undetected,undetected,undetected,undetected,malicious,undetected,undetected,undetected,undetected,malicious,undetected,malicious,undetected,timeout,undetected,undetected
```
