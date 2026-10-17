# Detections

KQL used in this lab. Paste any file into **Microsoft Sentinel → Logs** to run it.

| File | Type | Purpose |
| :--- | :--- | :--- |
| `rdp-bruteforce-auto-block.kql` | Scheduled analytics rule | Raises a High-severity incident when one IP has more than 50 failed logons (4625) in the last hour; mapped to MITRE ATT&CK T1110 |
| `failed-logons-by-country.kql` | Hunting | Geolocates attacker IPs and counts attempts per country |
| `failed-logons-by-ip-and-account.kql` | Hunting | Shows which usernames each IP tried (dictionary attack pattern) |
| `success-after-failures.kql` | Hunting | Flags any IP that brute-forced and then logged on successfully (4624) |
