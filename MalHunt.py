import requests
import json


RED, REGULAR, GREEN, YELLOW = '\33[31m', '\33[37m', '\33[32m', '\33[33m'

message = input(f"{YELLOW}\nHash, IP or Domain name?  {REGULAR}")[0].lower()
vt_api_key = "452b238d40cd7534a5a6478b3df82d6562e3509b9b83e46cf92ce881ccf51046"

if message == "h":
    hash_type = input(f"{YELLOW}hash type: {REGULAR}".lower())
    hash = "0e80d33ced80e0ad76f7784563699d7afc8c78d0cb4d146112850b2b76ac8936"


    Virus_total_hash = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey':vt_api_key, 'resource': hash}
    try:
        vt_get = requests.get(Virus_total_hash, params=params)
        vt_json = json.loads(vt_get.content)
        print(f"\n{YELLOW} VirusTotal:{REGULAR}\n  Scan Date: {vt_json['scan_date']}\n  Hash:{GREEN}{vt_json['resource']}{REGULAR}\n  Positives:{RED}{vt_json['positives']}{REGULAR}\n  Report: {vt_json['permalink']} \n ")
    except Exception:
        print("Nothing Here... \n")
    Malware_Bazzar = f"https://bazaar.abuse.ch/browse.php?search={hash_type}%3A{hash}"
    malbaz_get = requests.get(Malware_Bazzar)
    try:
        if "No data available in table" or "Wrong search term. Please re-check your search syntax" in malbaz_get.text:
            print(f"{YELLOW}Malware Bazaar: {REGULAR}\n {RED}the Hash doesn't exists in the database{REGULAR} \n ")
        else:
            print(f"{YELLOW}Malware Bazaar: {REGULAR}\n {GREEN}the hash Exists in the Database! \n Report Link:{Malware_Bazzar}")
    except Exception as err:
        print("Something Went Wrong")
    
    try:
        Malwares_com = f"https://www.malwares.com/report/file?hash={hash}"
        malcom_get = requests.get(Malwares_com)
        if malcom_get.status_code == 200:
            print(f"\n {YELLOW}Link For Full report on hash in Malwares.com:{REGULAR}\n {Malwares_com}")
        else:
            print("\n No results found..")
    except Exception:
        print("Something Went Wrong....")


if message == 'd':
    domain = input(f"{YELLOW}Domain Name: {REGULAR}").strip()
    Virus_total_ip = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': vt_api_key, 'domain': domain}
    vt_get = requests.get(Virus_total_ip, params=params)
    vt_json = json.loads(vt_get.content)
    # print(json.dumps(vt_json, indent=4, sort_keys=True))
    print(f"\n{YELLOW} VirusTotal:{REGULAR}\n  DomainName:{GREEN} {domain} {REGULAR}\n  score: {RED}{vt_json['Webutation domain info']['Safety score']}{REGULAR}  "
          f"Verdict: {RED}{vt_json['Webutation domain info']['Verdict']}  {REGULAR}\n  subdomains: {vt_json['subdomains']} \n  Report link: https://www.virustotal.com/gui/domain/{domain}\n")
    print(f"  {YELLOW}Domain Analysis On Abuse_IPDB : https://www.abuseipdb.com/check/{domain}{REGULAR} ")

if message == 'i':
    ip = input(f"{YELLOW}IP Address:  {REGULAR}").strip()
    Virus_total_ip = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {'apikey': vt_api_key, 'ip': ip}
    vt_get = requests.get(Virus_total_ip, params=params)
    vt_json = json.loads(vt_get.content)
    # print(json.dumps(vt_json, indent=4, sort_keys=True))
    print(f"\n{YELLOW} VirusTotal:{REGULAR}\n  IP:{GREEN} {ip} {REGULAR}\n  Positives: {RED}{vt_json['detected_urls'][0]} {REGULAR}\n  Owner: {vt_json['as_owner']} \n  Country:{GREEN}{vt_json['country']}{REGULAR} \n  Associated DomainNames: {vt_json['resolutions']} \n  Report Link: https://www.virustotal.com/gui/ip-address/{ip}\n")

    print(f"{YELLOW}  Domain Analysis On Abuse_IPDB : https://www.abuseipdb.com/check/{ip}{REGULAR} ")
