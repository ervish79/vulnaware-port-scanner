import socket
import concurrent.futures
import time
import json
import csv
import random
import requests # Moved to the top with the others

target = input("Enter the target IP (e.g. 10.143.32.229): ")

# 1. The NVD API Function (Moved up so the scanner can use it)
def check_nvd_api(software_banner):
    # We don't want to query the database if there is no banner
    if software_banner == "No banner" or software_banner == "":
        return "None"
        
    print(f"[*] Querying NVD database for: {software_banner[:20]}...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software_banner}"
    
    try:
        # Added a timeout so your scanner doesn't freeze if the API is slow
        response = requests.get(url, timeout=5) 
        if response.status_code == 200:
            data = response.json()
            if data.get('totalResults', 0) > 0:
                # Return the very first CVE ID found
                return data['vulnerabilities'][0]['cve']['id']
    except Exception as e:
        return f"API Error or Timeout"
        
    return "No known CVEs found via NVD"

# 2. A list to store our final report data
scan_report = []

def scan_port(port):
    # EVASION: Random sleep between 0.1 and 1.5 seconds
    time.sleep(random.uniform(0.1, 1.5))
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) 
    result = s.connect_ex((target, port))
    
    if result == 0:
        banner_text = "No banner"
        try:
            banner_text = s.recv(1024).decode().strip()
        except Exception:
            pass 
        
        # 3. DYNAMIC INTELLIGENCE: Ask the US Gov Database!
        # This replaces the old, static dictionary.
        alert = check_nvd_api(banner_text)
        
        # 4. Save the finding 
        finding = {
            "port": port,
            "banner": banner_text,
            "vulnerability_alert": alert
        }
        
        print(f"[+] Port {port} OPEN | Alert: {alert}")
        
        s.close()
        return finding 
        
    s.close()
    return None

print(f"\n[*] Starting Stealth Vulnerability Scan on: {target}")
print("-" * 60)

start_time = time.time()

# 5. Run the threads
# Note: Lowered to 20 workers. The NVD API will block you if you send 100 requests at the exact same time!
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(scan_port, range(1, 1025))

# Filter out the 'None' results
for res in results:
    if res is not None:
        scan_report.append(res)

end_time = time.time()
print("-" * 60)
print(f"[*] Scan Complete in {end_time - start_time:.2f} seconds.")

# 6. Save JSON
with open("scan_report.json", "w") as outfile:
    json.dump(scan_report, outfile, indent=4)
print("[*] JSON report saved to 'scan_report.json'")

# 7. Save CSV
csv_file = "scan_report.csv"
csv_columns = ["port", "banner", "vulnerability_alert"]

with open(csv_file, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
    writer.writeheader()
    for data in scan_report: 
        writer.writerow(data)
print(f"[*] CSV report saved to '{csv_file}'")
