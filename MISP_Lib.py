import requests, os, csv, urllib3, datetime, logging
import pandas as pd

from datetime import timedelta

# disable warning
logger = logging.getLogger("pymisp")
logger.disabled = True

urllib3.disable_warnings()

import warnings
warnings.filterwarnings('ignore')

from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from OTXv2 import OTXv2, IndicatorTypes

# logging
def setup_logger(name, log_file, level=logging.INFO):
    formatter = logging.Formatter('%(message)s')
    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


verify_log = setup_logger("verify_log",os.getcwd() + "/Desktop/Auto_VT/verify_log.log")
TI_log = setup_logger("TI_log",os.getcwd() + "/Desktop/Auto_VT/TI_log.log")

# Global data
SHA_INDEX = 0
CONTACTED_IP_INDEX = 1
CONTACTED_DOMAIN_INDEX = 2
CONTACTED_URL_INDEX = 3
EMBEDDED_IP_INDEX = 4
EMBEDDED_DOMAIN_INDEX = 5
EMBEDDED_URLS_INDEX = 6

SHA_256 = []
IPS = []
DOMAINS = []
URLS = []

misp = 0
misp_sp = 0
file_name = ""
first_write = 0
header = ["sha256", "ip", "domain","describe", "period"]


IOC_CATEGORY = {
    "HASH" : "Payload delivery",
    "IP" : "Network activity",
    "DOMAIN" : "Network activity",
    "URL" : "Network activity",
}

IOC_TYPE = {
    "HASH" : "sha256",
    "IP" : "ip-dst",
    "DOMAIN" : "domain",
    "URL" : "url",
}

# Class
class VT_API:
    def __init__(self, api_key):
        self.api_key = api_key
        self.url = "https://www.virustotal.com/api/v3/intelligence/search"
        self.headers = {"x-apikey": self.api_key}
    
    def vt_query(self, link):
        response = requests.get(link, headers=self.headers)
        return response.json()

    def export_hashdb(self, lst_samples, path_file):
        file = open(path_file, "a+")
        for sample in lst_samples:
            file.write(f"{sample}\n")
        file.close()
    
    def search_hashes(self, query):
        results = []
        has_next_page = False
        next_page = ""
        params = {"query": query, "limit": 20}

        response = requests.get(self.url, headers=self.headers, params=params)
        info = response.json()

        if "error" in info:
            TI_log.info("  [!] Fail to connect to VirusTotal !!")
            if info["error"]["message"] == "Quota exceeded":
                TI_log.info("    [!] No more Quota -> Exit !!")
            exit(0)

        results += info["data"]
        total_hash = info["meta"]["total_hits"]
        total_pages = int((total_hash / 20) + 1)

        if "next" in info["links"]:
            has_next_page = True
            next_page = info["links"]["next"]
        
        while has_next_page:
            response_con = requests.get(next_page, headers=self.headers)
            info_cont = response_con.json()
            results += info_cont["data"]

            if "next" in info_cont["links"]:
                has_next_page = True
                next_page = info_cont["links"]["next"]
            else:
                has_next_page = False
                
        return results

class HashAnalyzer:
    def __init__(self, api_key):
        self.api = VT_API(api_key)

    def get_api(self, link_query, isURL = False):
        info = self.api.vt_query(link_query)
        total_result = info["meta"]["count"]
        if total_result == 0:
            return []
        lst_result = []
        has_next_page = False
        next_page = ""
        total_pages = int((total_result / 10) + 1)
        total_ips_per_page = len(info["data"])

        if "next" in info["links"]:
            has_next_page = True
            next_page = info["links"]["next"]
        
        for i in range(total_ips_per_page):
            if isURL == False:                
                lst_result.append(info["data"][i]["id"])
            else:
                lst_result.append(info["data"][i]["context_attributes"]["url"])
        
        while has_next_page:
            info_cont = self.api.vt_query(next_page)

            total_ips_per_page = len(info_cont["data"])

            for i in range(total_ips_per_page):
                if isURL == False:
                    lst_result.append(info_cont["data"][i]["id"])
                else:
                    lst_result.append(info_cont["data"][i]["context_attributes"]["url"])
            
            if "next" in info_cont["links"]:
                has_next_page = True
                next_page = info_cont["links"]["next"]
            else:
                has_next_page = False
        return lst_result
        
    def analyze_hashes(self, query_hash, output_file):
        result = []
        hash_db = []
        response = self.api.search_hashes(query_hash)
        for sample in response:
            hash_db.append(sample["id"])
        link_samples = self.get_links(hash_db)
        contacted_ips, contacted_domains, contacted_urls, embedded_ips, embedded_domains = link_samples

        TI_log.info(f"  [+] Total samples: {len(hash_db)}")
        if len(hash_db) > 100:
            self.api.export_hashdb(hash_db, output_file + ".txt")
            TI_log.info("  [+] Getting Hashes")
        else:
            TI_log.info("  [+] Getting IOCs")
            for i in range(len(hash_db)):
                dic = dict() 
                TI_log.info(f"    [-] Hash {str((i + 1)).zfill(2)}: {hash_db[i]} => OK")
                dic.update({"sha256": hash_db[i]})
                dic.update({"contacted ips": ";".join(self.get_api(contacted_ips[i]))})
                dic.update({"contacted domains": ";".join(self.get_api(contacted_domains[i]))})
                dic.update({"contacted urls": ";".join(self.get_api(contacted_urls[i], True))})
                dic.update({"embedded ips": ";".join(self.get_api(embedded_ips[i]))})
                dic.update({"embedded domains": ";".join(self.get_api(embedded_domains[i]))})
                result.append(dic)
            df = pd.DataFrame.from_dict(result)
            df.to_csv(output_file + ".csv", index=False, header=True)

    def generate_links(self, samples, endpoint):
        return [f"https://www.virustotal.com/api/v3/files/{sample}/{endpoint}" for sample in samples]

    def get_links(self, samples):
        endpoints = [
            "contacted_ips", "contacted_domains", "contacted_urls",
           "embedded_ips", "embedded_domains", #"embedded_urls"
        ]
        links = [self.generate_links(samples, endpoint) for endpoint in endpoints]
        return links
    
class MISP:
    def __init__(self, url, key):
        self.url = url
        self.key = key
        self.api = ExpandedPyMISP(self.url, self.key, False, "json", proxies=None)

    def create_event(self, MISP_Event):
        event = self.api.add_event(MISP_Event, pythonify=True)
        TI_log.info("  [+] Created and Publish Event: %s" % event.id)
        return event
    
    def add_attribute_event(self, event_id, MISP_Attr):
        r = self.api.add_attribute(event_id, MISP_Attr)
        if "errors" in r:
            TI_log.info("    [!] Fail to add attribute for event %d - (%s)" % (event_id, MISP_Attr.value))
        else:
            TI_log.info("    [-] Added attribute for event %d - (%s)" % (event_id, MISP_Attr.value))
            return r
        
    def get_event_from_day(self, date):
        return self.api.search("events",date_from=date, date_to=date , pythonify=True)

    def get_event(self, event_id):
        event = self.api.get_event(event_id, pythonify=True)
        if event.get("errors") == None:
            return event
        else:
            TI_log.info("[!] Event id not valid !")
            return None
        
    def update_event(self, event_obj):
        self.api.update_event(event_obj)

class MISP_support:
    def __init__(self):
        pass
    
    def create_event_obj(self, info, tags = [], distrib=0, threat=1, analysis=0):
        event = MISPEvent()
        event.distribution = distrib
        event.threat_level_id = threat
        event.analysis = analysis
        event.info = info
        for tag in tags:
            event.add_tag(tag)
        return event
    
    def create_attr_obj(self, value, category, att_type, comment, to_ids, tags):
        misp_attribute = MISPAttribute()
        misp_attribute.value = str(value)
        misp_attribute.category = str(category)
        misp_attribute.type = str(att_type)
        misp_attribute.comment = str(comment)
        misp_attribute.to_ids = str(to_ids)
        for tag in tags:
            misp_attribute.add_tag(tag)
        return misp_attribute

def GetConfig(file_path):
    bIs_Existing = os.path.exists(file_path)
    if bIs_Existing == False:
        TI_log.info("  [!] Error: config file not found !!")
        exit(0)
    else:
        temp_arr = []
        with open(file_path,"r") as file:
            for line in file:
                temp = line.strip().split("=")
                for i in temp:
                    temp_arr.append(i.strip())
        it = iter(temp_arr)
        config = dict(zip(it, it))
        for i in config:
            if config[i] == "":
                TI_log.info("  [!] Found null setting !!")
                exit(0)
        return config

def create_hash_query():
    current_date = datetime.datetime.now()
    previous_date = current_date - timedelta(days=1)
    output_file = previous_date.strftime("iocs_%Y%m%d")
    condition = " (type:peexe OR type:pedll OR type:doc OR type:docx OR type:xls OR type:xlsx OR type:rtf OR type:zip OR type:rar OR type:lnk OR type:email OR type:7zip OR type:powershell OR type:CAB OR tag:contains-pe OR tag:direct-cpu-clock-access) NOT microsoft: Laroux.CN"
    formatted_date = previous_date.strftime("submitter:vn p:20+ p:50- fs:%Y-%m-%dT00:00:00+ fs:%Y-%m-%dT23:59:59-")
    return formatted_date + condition, output_file

def get_data_from_VT(api_key):
    TI_log.info("[x] Getting data from VT ...")
    query_hash, output_file = create_hash_query()
    TI_log.info("  [+] Using query: %s" % query_hash)
    file_path = os.getcwd() + "/Desktop/Auto_VT/VT_data/"
    if os.path.exists(file_path) == False:
        os.mkdir(file_path)
    file_path += output_file
    analyzer = HashAnalyzer(api_key)
    analyzer.analyze_hashes(query_hash, file_path)
    file_path += ".csv"
    TI_log.info("  [+] Get data: Done !!")
    TI_log.info("")
    return file_path

def ReadCSV(path):
    global SHA_256, IPS, DOMAINS, URLS

    with open(path) as file:
        csv_reader = csv.reader(file, delimiter=",")
        count = 0
        for i in csv_reader:
            if count == 0:
                count += 1
                continue
            else:
                for j, cursor in enumerate(i):
                    if j == "":
                        continue
                    else:
                        if cursor == "":
                            continue
                        temp = cursor.split(";")
                        if j == SHA_INDEX:
                            for data in temp:
                                SHA_256.append(data)
                        elif j == CONTACTED_IP_INDEX or j == EMBEDDED_IP_INDEX:
                            for data in temp:
                                IPS.append(data)
                        elif j == CONTACTED_DOMAIN_INDEX or j == EMBEDDED_DOMAIN_INDEX:
                            for data in temp:
                                DOMAINS.append(data)
                        elif j == CONTACTED_URL_INDEX or j == EMBEDDED_URLS_INDEX:
                            for data in temp:
                                URLS.append(data)

def CreateEvent():
    current_date = datetime.date.today()
    previous = current_date - datetime.timedelta(days=1)
    event_obj = misp_sp.create_event_obj(str(previous) + " VirusTotal",  ["type:OSINT","VirusTotal", "tlp:green"])
    a = misp.create_event(event_obj)
    return a

def AddAttribute(event):
    for i in SHA_256:
        att = misp_sp.create_attr_obj(i,IOC_CATEGORY["HASH"], IOC_TYPE["HASH"],"",1,["VirusTotal","type:OSINT"])
        misp.add_attribute_event(event.id, att)

    for i in IPS:
        att = misp_sp.create_attr_obj(i,IOC_CATEGORY["IP"], IOC_TYPE["IP"],"",1,["VirusTotal","type:OSINT"])
        misp.add_attribute_event(event.id, att)

    for i in DOMAINS:
        att = misp_sp.create_attr_obj(i,IOC_CATEGORY["DOMAIN"], IOC_TYPE["DOMAIN"],"",1,["VirusTotal","type:OSINT"])
        misp.add_attribute_event(event.id, att)

def import_from_csv(config, file_path):
    TI_log.info("[x] Doing import into MISP ...")
    global misp, misp_sp
    ReadCSV(file_path)
    misp = MISP(config["misp_url"], config["misp_key"])
    misp_sp = MISP_support()
    event = CreateEvent()
    AddAttribute(event)
    TI_log.info("  [+] Import: Done !! - Event info: %s" % (event.info))
    TI_log.info("")
    return event.id

def disable_warnings(event_id):
    TI_log.info("[x] Doing filtering ...")
    event = misp.get_event(event_id)
    if event != None:
        TI_log.info("  [+] Filter for event %s" % event_id)
        for i in event.Attribute:
            if i.get("warnings") != None:
                if i.to_ids == True:
                    i.to_ids = False
                    continue
    misp.update_event(event)
    TI_log.info("  [+] Filter: Done !!")
    TI_log.info("")

def VerifyEvent(config, event_obj):
    otx = OTXv2(config["otx_key"])
    for att in event_obj.Attribute:
        if att.type == "sha256" or att.type == "url":
            continue
        elif att.type == "domain":
            TYPE = IndicatorTypes.DOMAIN
        elif att.type == "ip-dst" or att.type == "ip-src":
            TYPE = IndicatorTypes.IPv4
        try:
            result = otx.get_indicator_details_by_section(TYPE, att.value, "general")
            if result["validation"] != []:
                att.to_ids = False
                att.comment = "Maybe FP, please do more check"
                verify_log.info("\t[+] %s is validated" % att.value)
        except:
            verify_log.info("\t[+] Fail to check %s" % att.value)
            continue
    return event_obj

def verify_ioc(config, event_id):
    TI_log.info("[x] Doing verify ...")
    now = datetime.datetime.today()
    date = now.strftime("%d-%m-%Y")
    verify_log.info("[+] Filter for event, event_id: %d - (date: %s)" % (event_id, date))
    event_obj = misp.get_event(event_id)
    event_obj = VerifyEvent(config, event_obj)
    misp.update_event(event_obj)
    verify_log.info("")
    TI_log.info("    [-] Result file: verify_log.log")
    TI_log.info("  [+] Verify: Done !!")
    TI_log.info("")

def WriteToFile(sha256,ips,domains, info, is_period):
    global header, first_write
    if is_period == True:
        period = "Yes"
    else:
        period = "No"
    with open(file_name, "a+", newline="") as file:
        writer = csv.writer(file)
        if first_write == 0:
            writer.writerow(header)
            first_write = 1
        for hash in sha256:
            write_arr = ["NULL","NULL","NULL",info]
            write_arr.append(period)
            write_arr[0] = write_arr[0].replace("NULL",hash)
            writer.writerow(write_arr)
        for ip in ips:
            write_arr = ["NULL","NULL","NULL",info]
            write_arr.append(period)
            write_arr[1] = write_arr[1].replace("NULL", ip)
            writer.writerow(write_arr)
        for domain in domains:
            write_arr = ["NULL","NULL","NULL",info]
            write_arr.append(period)
            write_arr[2] = write_arr[2].replace("NULL", domain)
            writer.writerow(write_arr)
    
def GetAttribute(event_attr):
    sha256 = []
    ip = []
    domain = []
    count = 0
    for i in event_attr:
        if i.to_ids == True:
            count += 1
            if i.type == "sha256":
                sha256.append(i.value)
            elif i.type == "ip-dst" or i.type == "ip-src":
                ip.append(i.value)
            elif i.type == "domain":
                domain.append(i.value)

    return sha256, ip, domain

def export_data(config):
    TI_log.info("[x] Exporting data ....")
    global file_name
    file_name = os.getcwd() + "/Desktop/Auto_VT/Export_Data/"
    if os.path.exists(file_name) == False:
        os.mkdir(file_name)
    misp = MISP(config["misp_url"], config["misp_key"])
    date = datetime.date.today()
    date_str = date.strftime("%Y_%m_%d")
    file_name += date_str + "_MISP_IOC.csv"
    TI_log.info("  [+] Export from day %s" % date.strftime("%d/%m/%Y"))
    events = misp.get_event_from_day(date_str)
    if len(events) == 0:
        TI_log.info("    [!] No event created in %s -> Exit" % previous.strftime("%d/%m/%Y"))
        TI_log.info("")
        exit(0)
    for event in events:
        TI_log.info("    [-] Event ID: %s" % event.id)
        is_period = True
        sha256, ip, domain = GetAttribute(event.Attribute)
        for i in event.tags:
            if i.name == "is_period:True":
                is_period = False
        WriteToFile(sha256, ip, domain, event.info, is_period)
    with open(file_name, "rb+") as file:
        file.seek(-2, os.SEEK_END)
        file.truncate()
    TI_log.info("    [-] File name: %s" % file_name.replace("Export_Data/",""))
    TI_log.info("  [+] Export: Done !!")
    TI_log.info("")
    return file_name
