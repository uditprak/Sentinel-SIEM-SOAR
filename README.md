# Sentin-Shield: Automated Cloud SOC & Honeypot

## 🚀 Overview
Sentin-Shield is a cloud-native Security Operations Center (SOC) project designed to observe, analyze, and automatically mitigate real-time brute-force attacks. By deploying a Windows-based Honeypot in Azure, I monitored global threat actors and implemented an automated response (SOAR) using Microsoft Sentinel and Logic Apps.

### 🛠️ Technologies Used
* **Cloud:** Microsoft Azure
* **SIEM/SOAR:** Microsoft Sentinel
* **Automation:** Azure Logic Apps
* **Firewall:** Network Security Group (NSG)
* **Query Language:** KQL (Kusto Query Language)
* **Threat Intel:** Shodan, IP Reputation DBs


---

![Architecture Diagram](architecture-diagram.png)



---

## 🔍 Phase 1: The Honeypot & Attack Observation
I deployed a Windows VM with an exposed RDP port to attract automated botnets. Within minutes, the VM was discovered and targeted.

### Key Observation: The Vietnam Spike
Using KQL, I identified a massive brute-force escalation.
* **Total Attempts:** 310+ Failed Logons.
* **Top Attacker Origin:** Vietnam / Romania.
* **Tactic:** High-frequency dictionary attacks on the `Administrator` and `Test` accounts.



```kql
// KQL to visualize the attack
SecurityEvent
| where EventID == 4625
| extend Country = tostring(geo_info_from_ip_address(IpAddress).country)
| summarize AttemptCount = count() by Country
| sort by AttemptCount desc
