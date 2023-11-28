# Network Vulnerability Scanner
By: Mohamed Yusuf, Banji Lawal, Faiz Khan, and Abimbola Ogundare

## Objective

This project aims to create a network vulnerability scanner, a vital tool for identifying and reporting potential vulnerabilities within a network's infrastructure. It aids network administrators and security professionals in proactively assessing and addressing security weaknesses, thereby preventing exploitation by attackers.

## Key Components

### Vulnerability Database
- Utilizes Vulners, a comprehensive database of known vulnerabilities, offering detailed information on severity, affected systems, and remediation steps.

### Vulnerability Scanning Engine
- Employs nmap, a powerful network scanning tool, to identify vulnerabilities within the network.
- Performs checks for open ports, service banners, software versions, configuration issues, and known vulnerabilities associated with them.

### CVSS Scoring
- Uses the Common Vulnerability Scoring System (CVSS) to assess and prioritize vulnerabilities, with higher scores indicating more severe vulnerabilities.

### Reporting Mechanism
- Generates detailed reports on detected vulnerabilities, including CVSS scores, affected systems, and remediation steps.

## Scanning Process

1. **Discovery**: Leverages nmap for identifying hosts and services within the target network through techniques like ping sweeps, port scans, and service detection.
   
2. **Vulnerability Assessment**: Uses nmap to compare discovered services with the Vulners database for known vulnerabilities based on service banners, software versions, and configurations.
   
3. **CVSS Scoring**: Assigns CVSS scores to identified vulnerabilities to prioritize them based on their potential impact and ease of exploitation.
   
4. **Reporting**: Categorizes and presents vulnerabilities in structured reports, enabling administrators to understand and take appropriate actions.
---

## Steps to Run Scanner
1. Within your terminal navigate to the Script Directory `cd c:/Users/User/Documents/GitHub/CIS460-Project`
2. Start the program using this script `python main.py`
---
