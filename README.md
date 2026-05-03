#  Vulnerability-Aware Port Scanner

A lightweight, multi-threaded network scanner built in Python. This tool performs high-speed port scanning, banner grabbing, and cross-references discovered services against a local threat intelligence dictionary to identify potential vulnerabilities.

**Category:** Offensive Security / Purple Team Tooling  
**Language:** Python 3.14

##  Disclaimer
**This tool was developed strictly for educational purposes and authorized testing in closed lab environments.** The author is not responsible for any misuse, damage, or illegal activities performed with this script. Only scan networks and devices you own or have explicit, written permission to test.

##  Features
* **High-Speed Execution:** Utilizes Python's `concurrent.futures.ThreadPoolExecutor` for rapid, multi-threaded scanning.
* **Service Detection (Banner Grabbing):** Interrogates open ports to identify running services and versions.
* **Vulnerability Mapping:** Automatically compares grabbed banners against a predefined list of known vulnerable software.
* **Structured JSON Reporting:** Outputs findings into a clean `scan_report.json` file, ready for SIEM integration or further data analysis.

##  Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ervish79/vulnaware-port-scanner.git](https://github.com/ervish79/vulnaware-port-scanner.git)
   cd vulnaware-port-scanner