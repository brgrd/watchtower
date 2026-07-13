---
generated_at: 2026-07-13T21:08:01.840862+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-10085 in Mattermost, CVE-2026-14453 in Centre, and CVE-2026-15545 in Shibby Tomato. These vulnerabilities expose internet-facing servers and applications to potential exploitation, with no patches currently available. The most time-sensitive action is to monitor and isolate systems running Mattermost versions 11.7.x <= 11.7.2, 11.6.x <= 11.6.4, 10.11.x <= 10.11.19, as they are vulnerable to exploitation.

## CVE-2026-10085: Mattermost RCE (risk: 70)
[P1] Mattermost versions 11.7.x <= 11.7.2, 11.6.x <= 11.6.4, 10.11.x <= 10.11.19 are vulnerable to RCE, with no patch available. Exploitation could lead to unauthorized access and data compromise. Why now: No patch is currently available for this vulnerability. (confidence: 0.80)

- [CVE-2026-10085](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-10085)

## CVE-2026-14453: Centre SSTI (risk: 70)
[P1] Centre is vulnerable to Server-Side Template Injection (SSTI), which could lead to RCE and data compromise. No patch is currently available. Why now: No patch is currently available for this vulnerability. (confidence: 0.80)

- [CVE-2026-14453](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-14453)

## CVE-2026-15545: Shibby Tomato Vulnerability (risk: 60)
[P2] Shibby Tomato up to 1.28.0000 is vulnerable to exploitation, with no patch currently available. This could lead to unauthorized access and data compromise. Why now: No patch is currently available for this vulnerability. (confidence: 0.70)

- [CVE-2026-15545](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15545)
