# MyDFIR-SOC Analyst Course

## Objective
This course created by Steven M was my main resource of practical knowledge led by a Cybersecurity expert with over 5 years of experience. This course included 8 chapters with about 15 sections diving into the technical skills of digital forensics and incident response. It taught me how to set up and manage my own lab, SIEM, and active directory environments as well as applying techniques used by SOC experts. I learned how to utilize various technical tools by completing this program such as email, endpoint, static & dynamic malware analysis, OSINT, and network analysis. I used this course as a great source for developing a sharper methodology when triaging alerts and performing digital forensic analysis. The methods I learned from conducting investigations and writing reports from this course gave me the knowledge I needed to become a better SOC Analyst. 

## SOC Environment
- Overview of the roles and challenges in a daily SOC environment
- Understanding the tools used in a SOC such as EDR, SIEM, IDS/IPS, IAM, SOAR, Case Management, etc.
- Dove into details of a typical MSSP environment, how shortcomings can arise from bad habits performed by analysts, and how to improve on them.
- Explore the Splunk system for a SIEM. Create reports, alerts, and indexes while using a proven method for filtering through Splunk events.
- Create well-designed Splunk dashboards for SSH activity, Windows events, and geolocation.<br>
<br>

![SSH Dashboard](https://github.com/user-attachments/assets/7019eb6e-2010-4b87-ba66-06d090ec84f4)
![Windows Dashboard](https://github.com/user-attachments/assets/6c1c7f51-4930-41d0-8897-d8fb3fe50919)
![Alerts in Splunk](https://github.com/user-attachments/assets/503d3310-bf0d-4ec2-a120-12c69b802d3d)

## Open Source Intelligence
- Utilize the power of doing OSINT on suspicious domains and IP addresses.
- Used OSINT tools such as whois, VirusTotal, nslookup, and AbuseIPDB to execute a stronger analysis.
- Perform better threat intelligence using OSINT.<br>
<br>

![Brute Force 3](https://github.com/user-attachments/assets/828e212d-0e6c-4640-9376-e961b1f982c2)

## Email Investigations
- Perform analysis on .eml documents to interpret phishing attempts by malicious senders.
- Focused on SPF, DKIM, and DMARC, and Reply-To authentication checks for better investigations.
- Understand the flow of email through the email servers from the sender to the receiver.
- Dive into the Content-Type parameter for attachments and decoding base64 emails.
- Perform OSINT on received IP addresses and the domain of the sender. <br>
<br>

![Screenshot 2024-10-05 032440](https://github.com/user-attachments/assets/458b9039-85a5-4b16-a47e-c03f2bdc65d4)

## Identity Access Management // Splunk
- Perform digital forensics in Splunk to investigate logins and activities performed by potential threat actors.
- Create a method for filtering through events by using the table & stats count by parameters in Splunk.
- Understand the Windows Event IDs for account creation, failed logins, and successful logins. (4720, 4625, 4624)
- Create a timeline of activity from initial login to processes created by potential threat actors.
- Perform OSINT on IP addresses that logged in to the endpoint.  <br>
<br>

![Screenshot 2024-10-24 055120](https://github.com/user-attachments/assets/0c2cf204-b3cd-4a0f-b6cd-7c347515a604)

## Network Analysis // Wireshark, Zeek, and Suricata
- Perform analysis using a .pcap file on both Wireshark and Zeek.
- Using Wireshark, perform forensics on HTTP streams, TLS v1.1 Certificates, and files in packet capture for deep investigations.
- Able to use Zeek as an additional network analysis tool: JA3 & JA3S hashes and investigate special network file log telemetry.
- Use a methodology of filtering out top conversations in big network packets for faster reporting.
- Perform OSINT on suspicious IP addresses found in packet capture.
- Use Suricata to detect with Suricata yaml rules. <br>
<br>

![Screenshot 2024-10-24 061159](https://github.com/user-attachments/assets/1ff74d6a-e7a9-4c13-b5b6-c1be896076ed)

![Screenshot 2024-10-10 083906](https://github.com/user-attachments/assets/ab8f8f3c-388b-40f2-8410-8f20c7b25917)

## Static Malware Analysis // .pdf, .xls, .dll, .exe, .js, yara rules
- Use exiftool for metadata information on malicious file, and perform OSINT of hash of file.
- PDF analysis: pdfid & peepdf to view objects in pdf. Use pdfparser to identify additional IOC files.
- XLS analysis: oleobj and oledump.py to analyze objects in file. Oleid to analyze malicious objects.
- Javascript analysis: View javascript code with Powershell IDE or Notepad ++. Use box-js for sandbox environment & js-beautify to organize javascript file.
- DLL & EXE analysis: Investigate with import hashes, 4D 5A (MZ) Headers, PEStudio, Detect it Easy, and capa rules. Analyze import and export functions of malware using malware tools.
- Create own yara rules for custom detection across environment. <br>
<br>

![Screenshot 2024-10-16 201617](https://github.com/user-attachments/assets/a979bfde-eac7-49f2-909e-caae71c62b2c)

![Screenshot 2024-10-16 203431](https://github.com/user-attachments/assets/c6c3437d-f518-49e2-899e-5ec59e00eb2e)

![Screenshot 2024-10-24 065351](https://github.com/user-attachments/assets/469e8f96-e2b9-46db-bf9e-a2075a8f14e8)


## Dynamic Malware Analysis
- Ensure the virtual sandbox environment is set up before executing malware.
- Obtain snapshots of the system using RegShot and AutoRun for comparison after malware execution.
- Use BurpSuite and Wireshark to analyze any TCP/HTTP traffic during malware execution.
- Use Process Explorer and Procmon to analyze the processes created during execution, especially for Write Functions. <br>
<br>

![Screenshot 2024-10-17 021924](https://github.com/user-attachments/assets/a127702b-32ea-46c7-8f00-57de62e65ed1)

![Screenshot 2024-10-17 022206](https://github.com/user-attachments/assets/a9901a64-98b9-40a0-a14a-fee4e5117b77)





