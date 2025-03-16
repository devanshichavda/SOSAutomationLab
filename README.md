# SOSAutomationLab
Objective

Developed a comprehensive cybersecurity home lab to detect and analyze malicious activity. The lab integrated a Windows virtual machine instrumented with Sysmon, a Wazuh server for security information and event management (SIEM), and TheHive for incident response. Leveraging DigitalOcean for infrastructure, the lab incorporated a custom workflow using Shuffler.io to automate alert enrichment with SHA256 regex matching and VirusTotal lookups, culminating in alert visualization within TheHive and email notifications. Mimikatz was utilized to generate security events and validate the efficacy of the implemented monitoring and response pipeline.

Skills Learned

- Security Information and Event Management (SIEM):
    - Deployed and configured Wazuh to collect, analyze, and correlate security logs from a Windows endpoint.
- Intrusion Detection System (IDS):
    - Utilized Sysmon and Wazuh to monitor system activity and detect potentially malicious behavior, exemplified by the detection of Mimikatz.
- Security Orchestration, Automation, and Response (SOAR):
    - Developed an automated workflow using Shuffler.io to enrich security alerts with threat intelligence from VirusTotal and streamline incident response.
- Incident Response:
    - Utilized TheHive to manage and track security alerts, facilitating investigation and response.
- Cloud Computing:
    - Leveraged DigitalOcean to provision and manage virtual machines for the lab environment.
- System Administration:
    - Installed and configured Ubuntu servers, including firewall management.
- Threat Intelligence:
    - Integrated VirusTotal API for real-time malware analysis and enrichment of security alerts.
- Regular Expressions:
    - Utilized regex for pattern matching within the Shuffler.io workflow.
- Virtualization:
    - Deployed and managed Windows virtual machines for testing and analysis.

Tools Used

- Sysmon:
    - For enhanced Windows system monitoring and logging.
- Wazuh:
    - As a Security Information and Event Management (SIEM) system.
- TheHive:
    - For incident response and case management.
- DigitalOcean:
    - Cloud platform for hosting virtual machines.
- Shuffler.io:
    - For security orchestration, automation, and response (SOAR).
- VirusTotal:
    - For threat intelligence and malware analysis.
- Mimikatz:
    - For security testing (generating security events).
- UTM:
    - For virtualization of the Windows environment.
- Ubuntu Server:
    - Operating system for Wazuh and TheHive servers.


Steps

1) Network Diagram
   <img width="697" alt="Screenshot 2025-03-16 at 3 21 54 PM" src="https://github.com/user-attachments/assets/cc76fc88-d070-46a1-b151-bd5918bb70c7" />
2) Virtual Machine Installation
   <img width="1222" alt="Screenshot 2025-03-16 at 3 24 49 PM" src="https://github.com/user-attachments/assets/fccb208a-f442-4f93-b8ea-767218c6aa00" />
3) Environment Setup: Deployed Ubuntu Server virtual machines on DigitalOcean to host Wazuh and TheHive. Configured firewall rules to secure the servers.<img width="783" alt="Screenshot 2025-03-16 at 3 28 09 PM" src="https://github.com/user-attachments/assets/9d05b908-dad0-422f-806c-dba04d36e1db" />
<img width="911" alt="Screenshot 2025-03-16 at 3 28 50 PM" src="https://github.com/user-attachments/assets/e5024bac-a156-435a-baa9-0e71e95d9bf4" />
<img width="916" alt="Screenshot 2025-03-16 at 3 29 07 PM" src="https://github.com/user-attachments/assets/f33db2bb-3eb7-4d3f-93e4-4ce15c26a5f3" />

4) Wazuh Deployment: Installed and configured the Wazuh server, including agent deployment on the Windows virtual machine.<img width="899" alt="Screenshot 2025-03-16 at 3 30 18 PM" src="https://github.com/user-attachments/assets/285e055e-00b0-4588-b6ff-7d5b4dac1988" />

5) Sysmon Installation: Installed Sysmon on the Windows VM to collect detailed system logs. <img width="1194" alt="Screenshot 2025-03-11 at 1 17 09 PM" src="https://github.com/user-attachments/assets/54c53b05-cd8c-4361-b347-80c5ea5324d2" />
6) TheHive Setup: Installed and configured TheHive for incident response and case management.<img width="784" alt="Screenshot 2025-03-16 at 3 27 22 PM" src="https://github.com/user-attachments/assets/89ef5ab1-93e0-4f86-8e25-0c94f47f12d5" />

7) Shuffler.io Workflow Creation: Developed a workflow in Shuffler.io to automate alert processing. This workflow included receiving alerts from Wazuh, performing SHA256 hash lookups     using regex, querying VirusTotal for threat intelligence, and updating TheHive cases with the enriched information.<img width="1108" alt="Screenshot 2025-03-16 at 3 33 15 PM" src="https://github.com/user-attachments/assets/4d22ff7f-1aa1-467e-bf59-f22d1dbab9d8" />

8) Alert Triggering: Executed Mimikatz on the Windows VM to generate security alerts and test the entire pipeline. <img width="1184" alt="Screenshot 2025-03-14 at 10 25 29 PM" src="https://github.com/user-attachments/assets/62e79321-6588-4170-b60b-951b5132d9bc" />

9) Email Integration: Configured email notifications for alerts generated within TheHive.<img width="1406" alt="Screenshot 2025-03-14 at 10 39 07 PM" src="https://github.com/user-attachments/assets/c207fed2-d0c1-43e2-818b-86779ccfb230" />

10) Validation: Verified successful alert flow from the Windows VM through Wazuh, Shuffler.io, VirusTotal, and finally to TheHive dashboard and email.<img width="481" alt="Screenshot 2025-03-14 at 10 26 00 PM" src="https://github.com/user-attachments/assets/5e931bef-e67f-49f2-8a0d-e8df7856b9c4" /> 
<img width="451" alt="Screenshot 2025-03-16 at 3 33 41 PM" src="https://github.com/user-attachments/assets/e25d2a12-5863-400e-b7d8-ca1e3c5fc129" />
