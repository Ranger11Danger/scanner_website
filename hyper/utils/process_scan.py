import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import requests
import json
from time import sleep
from bs4 import BeautifulSoup
from celery import shared_task
from hyper.dashboard.models import port_info
from celery_progress.backend import ProgressRecorder
import subprocess
import os
from .get_tenable_data import get_data

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



def parseXML(xmlfile):
    scan_result = []
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
    return scan_result

def get_xforce_info(stdcode):
    data = requests.get(f'https://api.xforce.ibmcloud.com/vulnerabilities/search/{stdcode}', auth=HTTPBasicAuth(API_KEY, API_PASS))
    return(data)

@shared_task(bind=True)
def process_cve(self,id , scan_port, address, slug,user_id):
    
    description, solution, cvss = get_data(id)
    
    try:
        port = port_info()
        port.name = id
        port.cve = id
        port.port = scan_port
        port.ip = address
        port.score = float(cvss)
        port.description = description
        port.solution = f"https://www.tenable.com/cve/{id}"
        port.scan_id = slug
        #TODO change this to set to current user not just admin
        port.user = int(user_id)
        port.save()
    except Exception as e:
        with open('/tmp/scan_log', 'wa') as file:
            file.write("error")

    return "Done"
@shared_task(bind=True)
def process_edb(self, id, scan_port, address, cve_text, uniq_list, slug, user_id):
    cve = convert(id.split(":")[-1])

    if cve not in cve_text:
        if cve.replace(f"{chr(92)}n","").strip().split()[0] == "N/A":
            return "Done"
        else:
            data = get_xforce_info(f'CVE-{cve.replace(f"{chr(92)}n","").strip().split()[0]}')
            data = json.loads(data.text)
            id = f'CVE-{cve.replace(f"{chr(92)}n","").strip().split()[0]}'
            name = data[0]['title']
            description = data[0]['description']
            cvss = data[0]['risk_level']
            solution = data[0]['remedy']
        if id in uniq_list:
            pass
        else:
            try:
                uniq_list.append(id)
                port = port_info()
                port.name = name
                port.cve = id
                port.port = scan_port
                port.ip = address
                port.score = cvss
                port.description = description
                port.solution = solution
                port.scan_id = slug
                port.user = int(user_id)
                port.save()
            except:
                pass
    return "Done"
        

def read_scan(scan, slug, user_id):
    scan_result = parseXML(scan)
    #progress_recorder = ProgressRecorder(self)
    cve_list = filter_results('cve', scan_result)
    edb_list = filter_results('exploitdb', scan_result)
    cve_text = [x.id for x in cve_list]
    scan_len = len(cve_list) + len(edb_list)
    temp = 0
    for cve in cve_list:
        #progress_recorder.set_progress(temp + 1, scan_len)
        process_cve.delay(cve.id, cve.port, cve.address, slug, user_id)
        sleep(.5)
        temp += 1
    uniq_list = cve_text
    for edbid in edb_list:
        #progress_recorder.set_progress(temp+ 1, scan_len)
        process_edb.delay(edbid.id, edbid.port, edbid.address, cve_text, uniq_list, slug, user_id)
        temp += 1
        sleep(.5)
    return "Done"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

@shared_task(bind=True)
def scan_target(self, target, slug,ports, custom_ports, user_id):
    if ports == 'top':
        subprocess.run(["nmap","-sV","--script=vulners", target, "-oX", f"{BASE_DIR}/scans/{target}.xml"])
    elif ports == 'all':
        subprocess.run(["nmap","-sV","-p 1-65535","--script=vulners", target, "-oX", f"{BASE_DIR}/scans/{target}.xml"])
    else:
        subprocess.run(["nmap","-sV",f"-p {custom_ports}","--script=vulners", target, "-oX", f"{BASE_DIR}/scans/{target}.xml"])

    read_scan(f"{BASE_DIR}/scans/{target}.xml", slug, user_id)

def scan_all(target_list, slug,ports, custom_ports, user_id):
    for target in target_list:
        scan_target.delay(target, slug, ports, custom_ports, user_id)