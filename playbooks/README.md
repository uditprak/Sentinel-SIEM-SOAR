# Playbooks (Azure Logic Apps)

## Notify-Security-Team
- **Trigger:** Microsoft Sentinel incident created by the `Auto-Block Brute Force` analytics rule.
- **Evidence:** two successful runs on 11 Feb 2026 (see `../Logic app succeed.png`).
- **Resource group:** Cyber-SOC-Lab (Central India).

## Planned response action: block the attacker IP
The intended remediation flow for this playbook:

1. Read the IP entity from the incident (`Entities - Get IPs`).
2. Add a high-priority **Deny** inbound rule for that IP to the honeypot VM's Network Security Group.
3. Add a comment to the Sentinel incident with the IP, rule name and time blocked.

## Export the workflow (to version-control it here)
1. Azure portal → Logic App `Notify-Security-Team` → **Logic app code view**.
2. Copy the JSON and save it as `notify-security-team.json` in this folder.
3. Remove any connection IDs or subscription IDs before committing.
