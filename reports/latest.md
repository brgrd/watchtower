---
generated_at: 2026-04-20T22:57:33.844797+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-20128 in Cisco Catalyst SD-WAN Manager, CVE-2026-20122 in Cisco Catalyst SD-WAN Manager, and CVE-2025-48700 in Synacor Zimbra Collaboration Suite. Internet-facing SD-WAN appliances and email servers are most exposed due to the lack of available patches for these vulnerabilities. The most time-sensitive action is to isolate and monitor Cisco Catalyst SD-WAN Manager and Synacor Zimbra Collaboration Suite, as no patches are currently available for these products.

## Cisco SD-WAN Vuln (risk: 100)
[P1] CVE-2026-20128 and CVE-2026-20122 in Cisco Catalyst SD-WAN Manager are being exploited in the wild, allowing attackers to gain access to sensitive information and execute arbitrary code. No patches are currently available. Why now: Reported exploitation in the wild (confidence: 0.90)

- [CVE-2026-20128](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20128)
- [CVE-2026-20122](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-20122)

## Zimbra Collaboration Vuln (risk: 100)
[P1] CVE-2025-48700 in Synacor Zimbra Collaboration Suite is being exploited in the wild, allowing attackers to execute arbitrary code via cross-site scripting. No patches are currently available. Why now: Reported exploitation in the wild (confidence: 0.90)

- [CVE-2025-48700](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-48700)

## PaperCut NG/MF Vuln (risk: 100)
[P1] CVE-2023-27351 in PaperCut NG/MF is being exploited in the wild, allowing attackers to bypass authentication. No patches are currently available. Why now: Reported exploitation in the wild (confidence: 0.90)

- [CVE-2023-27351](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27351)
