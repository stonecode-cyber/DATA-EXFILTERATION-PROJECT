# DATA-EXFILTERATION-PROJECT
DATA-EXFILTRATION-DETECTION-PROJECT

THIS IS MY DATA EXFILTRATION DETECTION HANDS ON PRACTICAL PROJECT WITH TRYHACKME

Data Exfiltration Analysis & Threat Hunting Lab: DNS Tunneling, FTP Exfiltration & HTTP POST Analysis. A hands-on network forensic and SIEM analysis project focusing on identifying covert data exfiltration vectors, investigating unauthorized file transfers, and detecting anomalous data streams using Splunk and Wireshark.

Table of Contents

Project Overview

Data Exfiltration Vectors & Attack Concepts

Tools & Technologies Used

Key Investigation Areas

Conclusion

📌 Project Overview

Data exfiltration is the unauthorized transfer of sensitive information from a compromised network. It represents the primary goal of many threat actors following an initial breach. This project focuses on detecting covert data exfiltration across multiple transport protocols (DNS, FTP, and HTTP) using SIEM log analysis and packet-level inspection to identify compromised hosts, exfiltrated file artifacts, and command-and-control (C2) domains.

⚙️ Data Exfiltration Vectors & Attack Concepts

Adversary Motivations:
Ransomware & Dual Extortion: Exfiltrating sensitive corporate files prior to system encryption to threaten public release.
Espionage & Sabotage: Exfiltrating proprietary intelligence or disrupting business operations.
Persistence & Reconnaissance: Maintaining long-term covert access while staging data for exfiltration.

Exfiltration Techniques & Categorization:
DNS Tunneling (Covert Channel): Encoding stolen data into domain name queries (e.g., base64 subdomains) sent to an attacker-controlled authoritative name server to bypass traditional firewall rules.

FTP File Transfer: Utilizing unencrypted file transfer protocols with administrative or guest credentials (root, guest) to stage and exfiltrate large database dumps or spreadsheets (customer_data.xlsx).
HTTP/HTTPS POST Exfiltration: Squeezing bulk data or stolen credentials inside HTTP POST request bodies, custom headers (X-Data), or multipart uploads to bypass size thresholds and evade DLP sensors.

🛠️ Tools & Technologies Used

Splunk SIEM: Querying DNS_logs indices using SPL (Splunk Processing Language) functions (stats count by query, len(query)) to detect high-entropy subdomain requests.
Wireshark Packet Analyzer: Protocol filtering (ftp contains, http.request.method == "POST", frame.len > 750), stream reassembly (Follow TCP/HTTP Stream), and payload decoding.

🔍 Key Investigation Areas

DNS Tunneling Detection (Splunk):
Identified suspicious high-volume DNS requests targeting malicious C2 domains (tunnelcorp.net).
Filtered long-string queries (where len(query) > 30) to isolate 315 instances of encoded DNS tunneling frames and map the primary internal source IP.

FTP Exfiltration Analysis (Wireshark):
Monitored unencrypted authentication streams to isolate guest access and compromised root credentials.
Extracted file artifacts (customer_data.xlsx, .csv files) by inspecting raw TCP streams and isolated the host responsible for large payload transfers (192.168.1.105).

HTTP/HTTPS POST Exfiltration (Wireshark):
Filtered high-volume HTTP POST requests (http.request.method == "POST" && frame.len > 750) to isolate internal host compromise (192.168.1.103).

Reconstructed HTTP request bodies to carve out hidden data flags and exfiltrated file streams.

🛡️ Conclusion

Detecting data exfiltration requires a layered monitoring strategy across both network proxies and SIEM platforms. By combining log correlation (tracking anomalous DNS query lengths in Splunk) with deep packet inspection (reconstructing HTTP POST and FTP streams in Wireshark), security analysts can detect covert exfiltration channels before proprietary data is fully compromised.
