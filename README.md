This project demonstrates a Security Operations Center (SOC) threat detection workflow using Splunk Enterprise SIEM and the Boss of the SOC (BOTS) v3 dataset — a real-world attack simulation dataset created by Splunk.
The project simulates what a SOC Analyst does daily: ingesting logs, writing detection queries, investigating attacks, building dashboards, and configuring alerts.

🎯 Objectives

Ingest and analyze over 2 million security events from a real attack scenario
Detect multiple attack types using SPL (Search Processing Language)
Build a live SOC dashboard with 5 detection panels
Configure automated alerts for brute force detection
Map all findings to the MITRE ATT&CK framework


🧰 Tools & Technologies
ToolPurposeSplunk Enterprise 10.2.3SIEM platform for log analysisBOTS v3 DatasetReal-world attack simulation dataSPLSplunk's Search Processing LanguageMITRE ATT&CKThreat intelligence framework

📊 Dataset
Boss of the SOC (BOTS) v3 — Official Splunk attack simulation dataset

Total Events: 2,083,056
Attack Date: August 20, 2018
Target: Fictional company "Frothy Beers"
Sourcetypes: 107 (Windows logs, network traffic, DNS, AWS, web server, etc.)
Hosts: 23+ machines


🔍 Detections & SPL Queries
1. 🌐 DNS High Volume Detection (C2 Beaconing)
MITRE ATT&CK: T1071.004 — Application Layer Protocol: DNS
splindex=botsv3 earliest=0 sourcetype="stream:dns"
| stats count by src_ip
| where count > 1000
| sort -count
Finding: IP 172.31.12.76 made 29,395 DNS queries — indicating potential C2 beaconing activity.

2. 🔑 SuiteCRM Brute Force Detection
MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing
splindex=botsv3 earliest=0 sourcetype="stream:http"
uri_path="/suitecrm/index.php"
| stats count by src_ip, http_method
| sort -count
Finding: IP 192.168.8.112 made 150 requests to the SuiteCRM login page — coordinated brute force from 4 IPs in same subnet (192.168.8.x).

3. ☁️ AWS Metadata Theft Detection
MITRE ATT&CK: T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
splindex=botsv3 earliest=0 sourcetype="stream:http"
uri_path="/latest/meta-data/instance-id"
| stats count by src_ip
| sort -count
| head 10
Finding: IP 172.31.12.76 attempted to access AWS instance metadata 121 times — attempting to steal cloud credentials.

4. 📤 Data Exfiltration Detection
MITRE ATT&CK: T1041 — Exfiltration Over C2 Channel
splindex=botsv3 earliest=0 sourcetype="stream:ip"
| stats sum(bytes_out) by src_ip
| sort -"sum(bytes_out)"
| head 10
Finding: IP 172.16.133.131 sent 218 MB of outbound data — potential data exfiltration.

5. ⏱️ Attack Event Timeline
MITRE ATT&CK: Multiple Techniques
splindex=botsv3 earliest=0
| timechart count span=1h
Finding: Attack began at 14:00 on August 20, 2018 with a massive spike from ~76 to 371,193 events per hour — indicating a coordinated multi-wave APT attack.

📈 SOC Dashboard
Built a live 5-panel SOC Threat Detection Dashboard in Splunk:
PanelDescriptionDNS High Volume Source IPsTop IPs making excessive DNS queriesSuiteCRM Brute Force AttackersIPs hammering CRM loginAWS Metadata Theft AttemptsCloud credential theft attemptsTop Data Exfiltration SourcesIPs sending most outbound dataAttack Event TimelineFull attack timeline visualization

🚨 Alerts Configured
Alert NameTrigger ConditionScheduleSuiteCRM Brute Force AlertAny IP hits login > 50 timesEvery hour

🗺️ MITRE ATT&CK Mapping
Technique IDTechnique NameDetectionT1110.001Brute Force: Password GuessingSuiteCRM login attemptsT1071.004Application Layer Protocol: DNSHigh volume DNS queriesT1552.005Cloud Instance Metadata APIAWS metadata endpoint accessT1041Exfiltration Over C2 ChannelLarge outbound data transfersT1046Network Service DiscoveryPort scanning activity

🔑 Key Findings
Primary Suspect IP: 172.31.12.76
This IP appeared across multiple attack vectors:

🔴 Top DNS query source (29,395 queries)
🔴 AWS metadata theft (121 attempts)
🔴 High network traffic volume

Attack Timeline Summary
09:00 - 13:00  →  Normal activity
14:00          →  Attack begins (371,193 events/hour spike)
14:00 - 17:00  →  First attack wave
18:00          →  Brief pause
19:00          →  Second wave (400,000+ events/hour)
20:00 - 21:00  →  Attack winds down

📁 Project Structure
splunk-soc-threat-detection/
│
├── README.md                    # Project documentation
├── queries/
│   ├── dns_detection.spl        # DNS beaconing detection
│   ├── brute_force.spl          # Brute force detection
│   ├── aws_metadata.spl         # AWS metadata theft
│   ├── data_exfiltration.spl    # Data exfiltration
│   └── attack_timeline.spl      # Attack timeline
├── screenshots/
│   ├── dashboard.png            # SOC dashboard
│   ├── brute_force_results.png  # Brute force detection
│   ├── dns_results.png          # DNS analysis
│   └── timeline.png             # Attack timeline chart


🚀 How to Reproduce

Install Splunk Enterprise (free trial at splunk.com)
Download BOTS v3 dataset from github.com/splunk/botsv3
Install dataset via Apps → Install from file
Run queries from the /queries folder
Build dashboard using Save As → Add to Dashboard


👤 Author
Sanju K S

Network Support Executive → Aspiring SOC Analyst
GitHub: @sanjuGowdaa
Location: Bangalore, India


📚 References

Splunk BOTS v3 Dataset
MITRE ATT&CK Framework
Splunk SPL Documentation
ShareContentpdf
