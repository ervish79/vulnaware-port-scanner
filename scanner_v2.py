import socket
import concurrent.futures
import time
import json

target = input("Enter the taget ip{e.g 10.123.123.123}")

# 1. Our Mini "Threat Intelligence" Database
# In a real company, this would connect to the NIST NVD database API.
known_vulnerabilities = {
    "VMware Authentication Daemon Version 1.10": "CRITICAL: Potential Buffer Overflow (CVE-2009-XXXX)",
    "vsFTPd 2.3.4": "CRITICAL: Smiley Face Backdoor (CVE-2011-2523)",
    "FreeFloat": "HIGH: Known Buffer Overflow",
}

# 2. A list to store our final report data
scan_report = []

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) 
    result = s.connect_ex((target, port))
    
    if result == 0:
        banner_text = "No banner"
        try:
            banner_text = s.recv(1024).decode().strip()
        except Exception:
            pass 
        
        # 3. Check the banner against our Threat Intel database
        alert = "None"
        for vulnerable_software, cve_alert in known_vulnerabilities.items():
            if vulnerable_software in banner_text:
                alert = cve_alert
        
        # 4. Save the finding as a structured dictionary (JSON format)
        finding = {
            "port": port,
            "banner": banner_text,
            "vulnerability_alert": alert
        }
        
        print(f"[+] Port {port} OPEN | Alert: {alert}")
        return finding # Return the data instead of just printing it
        
    s.close()
    return None

print(f"[*] Starting Vulnerability Scan on: {target}")
print("-" * 50)

start_time = time.time()

# 5. Run the threads and collect the data
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    # We use executor.map to easily collect the returned 'finding' dictionaries
    results = executor.map(scan_port, range(1, 1025))

# Filter out the 'None' results (closed ports)
for res in results:
    if res is not None:
        scan_report.append(res)

end_time = time.time()
print("-" * 50)
print(f"[*] Scan Complete in {end_time - start_time:.2f} seconds.")

# 6. Save the final report to a JSON file!
with open("scan_report.json", "w") as outfile:
    json.dump(scan_report, outfile, indent=4)

print("[*] Report saved automatically to 'scan_report.json'")