import requests
import json
from datetime import datetime, timedelta, timezone
import csv
import os
import re
import time
import sys
DB_FILE = "vuln.csv"

def format_cve_for_telegram(cve):
    def escape_html(text):
        return re.sub(r"[<>&]", lambda x: {"<": "&lt;", ">": "&gt;", "&": "&amp;"}[x.group()], text)

    cve_id = escape_html(cve.get("id", "Unknown CVE"))
    description = escape_html(cve.get("description", "No description available."))
    base_severity = escape_html(cve.get("baseSeverity", "N/A"))
    main_url = f"https://nvd.nist.gov/vuln/detail/{cve.get('id', 'Unknown CVE')}"

    if cve.get("baseSeverity") == "CRITICAL":
        cve_id = f"🔥<b>{cve_id}</b>🔥"
    else:
        cve_id = f"<b>{cve_id}</b>"
    links=""
    for entry in cve.get("references"):
        url=entry.get("url")
        links +="<a href=\""+url+"\">"+url+"</a>\n"
    
    message=f'<a href="{main_url}">{cve_id}</a>\n'

    if has_exploit(cve)==True:
        message+=f'#exploit '

    if "wordpress" in description.lower():
        message+=f'#Wordpress '

    message+=f'#{base_severity.lower()} '

    for cwe in cve['weakness']:
        if map_cwe_tags(cwe)!=False:
            message+=f'#{map_cwe_tags(cwe)}'

    message+=f'\n\n'
    message+=f'<pre>{description}</pre>\n'
    message+=f'{links}'

    print(message)
    return message



def send_telegram_message(message):
    token = os.getenv('TELEGRAM_BOT')
    chat_id = os.getenv('TELEGRAM_GROUP')
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML"
    }
    
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

#replace with the tags
def is_cwe_in_list(cwe):
    cwe_list = [
        "CWE-22", "CWE-23", "CWE-35", "CWE-359",
        "CWE-538", "CWE-548", "CWE-552", "CWE-566", "CWE-862", "CWE-863",
        "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-88", "CWE-89",
        "CWE-90", "CWE-91", "CWE-94", "CWE-95", "CWE-96", "CWE-97",
        "CWE-98", "CWE-564", "CWE-643", "CWE-652", "CWE-917",
        "CWE-918"
    ]
    return cwe in cwe_list

def map_cwe_tags(cwe):
    match cwe:
        case "CWE-22":
            return "Traversal"
        case "CWE-23":
            return "Traversal"
        case "CWE-35":
            return "Traversal"
        case "CWE-359":
            return "Exposure"
        case "CWE-538":
            return "Disclosure"
        case "CWE-548":
            return "Disclosure"
        case "CWE-552":
            return "Auth"
        case "CWE-566":
            return "SQL"
        case "CWE-862":
            return "Auth"
        case "CWE-863":
            return "Auth"
        case "CWE-77":
            return "RCE"
        case "CWE-78":
            return "RCE"
        case "CWE-79":
            return "XSS"
        case "CWE-80":
            return "XSS"
        case "CWE-88":
            return "SQL"
        case "CWE-89":
            return "SQL"
        case "CWE-90":
            return "LDAP"
        case "CWE-91":
            return "XML"
        case "CWE-94":
            return "RCE"
        case "CWE-95":
            return "RCE"
        case "CWE-96":
            return "RCE"
        case "CWE-97":
            return "SSI"
        case "CWE-98":
            return "RFI"
        case "CWE-564":
            return "SQL"
        case "CWE-643":
            return "XPath"
        case "CWE-652":
            return "XQuery"
        case "CWE-917":
            return "ELI"
        case "CWE-918":
            return "SSRF"

    return False



def convert_to_markdown(data):
    markdown = f"# {data.get('id', 'Unknown ID')}\n\n"
    markdown += f"**{data.get('published', 'Unknown')}**\n\n"
    markdown += "## Description\n"
    markdown += f"{data.get('description', 'No description available.')}\n\n"
    if has_exploit(data)==True:
        markdown += f"![](https://img.shields.io/static/v1?label=Exploit&message=Yes&color=red)\n"
    markdown += f"![](https://img.shields.io/static/v1?label=Score&message={data.get('baseScore', 'N/A')}&color=red)\n"
    markdown += f"![](https://img.shields.io/static/v1?label=Severity&message={data.get('baseSeverity', 'N/A')}&color=red)\n"

    for cwe in data['weakness']:
        if map_cwe_tags(cwe)!=False:
            markdown+=f'![](https://img.shields.io/static/v1?label=CWE&message={map_cwe_tags(cwe)}&color=green)'
    if "wordpress" in data.get('description'):
        markdown+=f'![](https://img.shields.io/static/v1?label=System&message=Wordpress&color=red)'
    markdown += f"\n\n"

    markdown += "## Links\n"
    for entry in data.get("references"):
        url=entry.get("url")
        markdown +=f'- [{url}]({url})\n'




    return markdown


def initialize_db():

    if not os.path.exists(DB_FILE):
        with open(DB_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["CVE_NAME", "Severity", "hasExploit", "hasNuclei","Added"])

def entry_exists(cve_name):
    with open(DB_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["CVE_NAME"] == cve_name:
                return True
    return False

def update_entry(cve_name, severity, has_exploit, has_nuclei,added):
    updated = False
    rows = []

    with open(DB_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["CVE_NAME"] == cve_name:
                row["Severity"] = severity
                row["hasExploit"] = has_exploit
                row["hasNuclei"] = has_nuclei
                row["Added"] = added
                updated = True
            rows.append(row)
    if not updated:
        rows.append({
            "CVE_NAME": cve_name,
            "Severity": severity,
            "hasExploit": has_exploit,
            "hasNuclei": has_nuclei,
            "Added": added
        })

    with open(DB_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["CVE_NAME", "Severity", "hasExploit", "hasNuclei","Added"])
        writer.writeheader()
        writer.writerows(rows)

    return updated


def remove_entry(cve_name):
    rows = []
    entry_removed = False

    with open(DB_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["CVE_NAME"] != cve_name:
                rows.append(row)
            else:
                entry_removed = True
    with open(DB_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["CVE_NAME", "Severity", "hasExploit", "hasNuclei","Added"])
        writer.writeheader()
        writer.writerows(rows)
    return entry_removed


def update_column_by_cve(cve_name, column_name, new_value):
    updated = False
    rows = []

    with open(DB_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        fieldnames = reader.fieldnames

        if column_name not in fieldnames:
            raise ValueError(f"Column '{column_name}' does not exist in the file.")
        for row in reader:
            if row["CVE_NAME"] == cve_name:
                row[column_name] = new_value 
                updated = True
            rows.append(row)
    with open(DB_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return updated

def get_column_value_by_cve(cve_name, column_name):

    with open(DB_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        fieldnames = reader.fieldnames

        if column_name not in fieldnames:
            raise ValueError(f"Column '{column_name}' does not exist in the file.")
        for row in reader:
            if row["CVE_NAME"] == cve_name:
                return row[column_name] 

    return None  


def upsert_in_folder(cve):
    folder_path="./nvd"
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    cve_year = cve['id'].split("-")[1]
    cve_severity = cve['baseSeverity']
    cve_year_path=os.path.join(folder_path, cve_year)
    if not os.path.exists(cve_year_path):
        os.makedirs(cve_year_path)
    cve_folder_path=os.path.join(cve_year_path, cve_severity)
    if not os.path.exists(cve_folder_path):
        os.makedirs(cve_folder_path)
        
    cve_folder_entry=os.path.join(cve_folder_path, cve['id'])
    if not os.path.exists(cve_folder_entry):
        os.makedirs(cve_folder_entry)

    cve_file_md=os.path.join(cve_folder_entry, "README.md")
    cve_file_json=os.path.join(cve_folder_entry, cve['id']+".json")
    isEntryExist=False
    if os.path.exists(cve_file_json):
        isEntryExist=True

    with open(cve_file_json, 'w') as file:
        json.dump(cve["nvd"], file, indent=4)

    with open(cve_file_md, 'w') as file:
        file.write(convert_to_markdown(cve))
    

    if isEntryExist:
        update_column_by_cve(cve['id'], "Severity", cve.get('baseSeverity'))
        update_column_by_cve(cve['id'], "hasExploit", cve.get('hasExploit'))
        update_column_by_cve(cve['id'], "hasNuclei", "false")
        return False
    



    update_entry(cve.get('id'),cve.get('baseSeverity'), cve.get('hasExploit'), "false",datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"))
    
    return True



def fetch_cve_data():
    end_time = datetime.now(timezone.utc)

    start_time = end_time - timedelta(hours=24)
    pub_start_date = start_time.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end_date = end_time.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={pub_start_date}&pubEndDate={pub_end_date}"
    headers = {
        "apiKey": os.getenv('NVD_KEY')
    }
    response = requests.get(url,headers=headers)
    response.raise_for_status() 
    data = response.json()
    return data

def extract_cve_info(data):
    vulnerabilities = data.get("vulnerabilities", [])
    extracted_info = []
    
    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve", {})
        cve_id = cve.get("id")
        vulnStatus=cve.get("vulnStatus")
        published=datetime.fromisoformat(cve.get("published")).strftime("%Y-%m-%d %H:%M:%S")
        descs = cve.get("descriptions", [])
        description = None
        for desc in descs:
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        

        cvssMetricV40 = cve.get("metrics", {}).get("cvssMetricV40", [])
        cvssMetricV31 = cve.get("metrics", {}).get("cvssMetricV31", [])
        cvssMetricV2 = cve.get("metrics", {}).get("cvssMetricV2", [])

        baseScore = None
        baseSeverity = None
        attackVector=None
        complexity=None
        if cvssMetricV40:
            baseScore = cvssMetricV40[0].get("cvssData", {}).get("baseScore")
            baseSeverity = cvssMetricV40[0].get("cvssData", {}).get("baseSeverity")
            attackVector = cvssMetricV40[0].get("cvssData", {}).get("attackVector")
            complexity= cvssMetricV40[0].get("cvssData", {}).get("attackComplexity")

        elif cvssMetricV31:
            baseScore = cvssMetricV31[0].get("cvssData", {}).get("baseScore")
            baseSeverity = cvssMetricV31[0].get("cvssData", {}).get("baseSeverity")
            attackVector = cvssMetricV31[0].get("cvssData", {}).get("attackVector")
            complexity= cvssMetricV31[0].get("cvssData", {}).get("attackComplexity")

        elif cvssMetricV2:
            baseScore = cvssMetricV2[0].get("cvssData", {}).get("baseScore")
            baseSeverity = cvssMetricV2[0].get("baseSeverity")
            attackVector = cvssMetricV31[0].get("cvssData", {}).get("accessVector")
            complexity= cvssMetricV31[0].get("cvssData", {}).get("accessComplexity")
        if baseSeverity!="CRITICAL" and baseSeverity!="HIGH":
            print(f"{cve_id} skip  due to {baseSeverity}")
            continue 

        if attackVector!="NETWORK" and complexity!="LOW":
            print(f"{cve_id} skip due to {attackVector}")
            print(f"{cve_id} skip  due to {complexity}")
            continue 

        if "firmware" in description.lower():
            print(f"{cve_id} skip  due to firmware")
            continue
        isValid=False
        weakness_array=[]
        weaknesses = cve.get("weaknesses", [])
        for entry in weaknesses:
            desc=entry.get("description",[])
            if is_cwe_in_list(desc[0].get("value")):
                isValid=True
                weakness_array.append(desc[0].get("value"))
        
        if isValid==False:
            print(f"{cve_id} skip due to CWE's")
            continue
        print(f"{cve_id} will be added")
        #check if have exploit   
        hasExploit=False 
        references = cve.get("references", [])
        for entry in references:
            for tag in entry.get("tags",[]):
                if tag=="Exploit":
                    hasExploit=True

        if baseScore:
            extracted_info.append({
                "id": cve_id,
                "published":published,
                "vulnStatus":vulnStatus,
                "description": description,
                "baseScore": baseScore,
                "baseSeverity": baseSeverity,
                "hasExploit":hasExploit,
                "weakness":weakness_array,
                "references": cve.get("references", []),
                "nvd":vulnerability
            })
    
    return extracted_info

def get_all_json_file_paths(root_dir):
    json_file_paths = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith('.json'):
                json_file_paths.append(os.path.join(dirpath, filename))

    return json_file_paths

def load_entry(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data


def get_severity(cve):

    cvssMetricV40 = cve.get("metrics", {}).get("cvssMetricV40", [])
    cvssMetricV31 = cve.get("metrics", {}).get("cvssMetricV31", [])
    cvssMetricV2 = cve.get("metrics", {}).get("cvssMetricV2", [])
    baseSeverity = None
    if cvssMetricV40:
        baseSeverity = cvssMetricV40[0].get("cvssData", {}).get("baseSeverity")

    elif cvssMetricV31:
        baseSeverity = cvssMetricV31[0].get("cvssData", {}).get("baseSeverity")

    elif cvssMetricV2:
        baseSeverity = cvssMetricV2[0].get("baseSeverity")

    
    return baseSeverity



def has_exploit(cve):
    references = cve.get("references", [])
    for entry in references:
        for tag in entry.get("tags",[]):
            if tag=="Exploit":
                return True
    return False

def request_cve(cve):
    print(f"Request: {cve.get('id')}")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve.get('id')}"
    headers = {
        "apiKey": os.getenv('NVD_KEY')
    }
    response = requests.get(url,headers=headers)
    response.raise_for_status() 
    data = response.json()
    time.sleep(2) 
    return data



def main():
    update=False
    if len(sys.argv) > 1:
        update = sys.argv[1].lower() == "true"
    initialize_db()
    try:
        cve_data = fetch_cve_data()
        cve_info = extract_cve_info(cve_data)
        for cve in cve_info:
            notification=upsert_in_folder(cve)
            if notification==True:
                time.sleep(5) 
                send_telegram_message(format_cve_for_telegram(cve))
    except Exception as e:
        print(f"Error: {e}")
    if update != True:
        return
    #loading all files    
    root_directory = "nvd" 
    json_paths = get_all_json_file_paths(root_directory)
    for path in json_paths:
        #load the path 
        cve=load_entry(path)
        cve=cve.get('cve',{})

        if get_column_value_by_cve(cve.get('id'), "Added") is None:
            update_entry(cve.get('id'),get_severity(cve), has_exploit(cve), "false",datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"))


        cve_date=datetime.strptime(get_column_value_by_cve(cve.get('id'), "Added"), "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
        current_date = datetime.now(timezone.utc)
        if cve_date<(current_date - timedelta(days=90)):
            print(f"{cve.get('id')} will be skipped because it's too old" )
            continue
        if has_exploit(cve)==True:
            continue
 

        try:
            print(f"{cve.get('id')} updating entry...")
            cve=request_cve(cve)
            cve_info = extract_cve_info(cve)
            if len(cve_info) <= 0:
                continue
            cve=cve_info[0]
            upsert_in_folder(cve)
            if has_exploit(cve)==True:
                upsert_in_folder(cve)
                time.sleep(5)
                send_telegram_message(format_cve_for_telegram(cve))
        except Exception as e:
            print(f"Error: {e}")




if __name__ == "__main__":
    main()