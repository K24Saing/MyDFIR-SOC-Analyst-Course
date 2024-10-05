# MyDFIR-SOC Analyst Course

## Objective
This course created by Steven M was my main resource of practical knowledge led by a Cybersecurity expert with over 5 years of experience. This course included 8 chapters with about 15 sections diving into the technical skills of digital forensics and incident response. It taught me how to set up and manage my own lab, SIEM, and active directory environments as well as applying techniques used by SOC experts. I used this course as a great source for developing a sharper methodology when triaging alerts and performing digital forensic analysis. The methods I learned from conducting investigations and writing reports from this course gave me the knowledge I needed to become a better SOC Analyst. 

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

## Identity Access Management // IAM
- Perform digital forensics in Splunk to investigate logons and activities performed by potential threat actors.
- Create a method for filtering through events by using the table & stats count by parameters in Splunk.
- Understand the Windows Event IDs for account creation, failed logins, and successful logins. (4720, 4625, 4624)
- Create a timeline of activity from initial login to processes created by potential threat actors.
- Perform OSINT on IP addresses that logged in to the endpoint.  <br>
<br>

![Screenshot 2024-10-05 033950](https://github.com/user-attachments/assets/891037b6-96d3-433e-97e3-1aae58630cea)



