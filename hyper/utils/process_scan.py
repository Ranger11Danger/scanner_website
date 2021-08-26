import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import requests
import json
from bs4 import BeautifulSoup

API_KEY = '25fe06fb-0c6b-475a-9963-59767924c909'
API_PASS = '53692957-ab54-4712-9716-884b10b82e1a'

class vulners_result:
    def __init__(self, type: str, id: str, is_exploit: bool, cvss: float, port: int, address: str ) -> None:
        self.type = type
        self.id = id
        self.is_exploit = is_exploit
        self.cvss = cvss
        self.port = port
        self.address = address

def filter_results(type, scan):
    return [x for x in scan if x.type == type]

def convert(edbid):
    import requests

    url = f"https://www.exploit-db.com:443/exploits/{edbid}"
    headers = {"Sec-Ch-Ua": "\"Chromium\";v=\"91\", \" Not;A Brand\";v=\"99\"", "Sec-Ch-Ua-Mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    data = requests.get(url, headers=headers)
    soup = BeautifulSoup(data.text, 'html.parser')

    result = soup.findAll('h6')
    return(result[1].text.strip())


scan_result = []
def parseXML(xmlfile):
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    info = root.find("host")
    addr = info.find("address").get('addr')
    items = info.find('ports')
    for item in items: 
        
        try:
            portid = item.get('portid')
            for i in item.find('script').find('table'):
                data = list(i)
                for key in data:
                    if 'cvss' in key.items()[0]:
                        cvss = key.text
                    elif 'is_exploit' in key.items()[0]:
                        is_exploit = key.text
                    elif 'type' in key.items()[0]:
                        type = key.text
                    elif 'id' in key.items()[0]:
                        id = key.text
                scan_result.append(vulners_result(type, id, is_exploit, cvss, portid, addr))
            
        except:
            pass

def get_xforce_info(stdcode):
    data = requests.get(f'https://api.xforce.ibmcloud.com/vulnerabilities/search/{stdcode}', auth=HTTPBasicAuth(API_KEY, API_PASS))
    return(data)

def read_scan(scan):
    parseXML(scan)

    cve_list = filter_results('cve', scan_result)
    edb_list = filter_results('exploitdb', scan_result)
    cve_text = [x.id for x in cve_list]

    for cve in cve_list:
        data = get_xforce_info(cve.id)
        data = json.loads(data.text)
        cve.name = data[0]['title']
        cve.description = data[0]['description']
        cve.cvss = data[0]['risk_level']
        cve.solution = data[0]['remedy']

    uniq_list = []
    for edbid in edb_list:
        cve = convert(edbid.id.split(":")[-1])

        if cve not in cve_text:
            if cve.replace(f"{chr(92)}n","").strip().split()[0] == "N/A":
                continue
            data = get_xforce_info(f'CVE-{cve.replace(f"{chr(92)}n","").strip().split()[0]}')
            data = json.loads(data.text)
            edbid.id = f'CVE-{cve.replace(f"{chr(92)}n","").strip().split()[0]}'
            edbid.name = data[0]['title']
            edbid.description = data[0]['description']
            edbid.cvss = data[0]['risk_level']
            edbid.solution = data[0]['remedy']
            if edbid.id in uniq_list:
                continue
            else:
                uniq_list.append(edbid.id)
                print(edbid)
            cve_list.append(edbid) 

    return(cve_list)

