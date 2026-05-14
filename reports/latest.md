---
generated_at: 2026-05-14T10:28:55.916084+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-46445 in SOGo, CVE-2026-5361 in Envira Gallery Lite, and CVE-2026-7525 in My Calendar. Internet-facing web servers and WordPress installations are most exposed due to the lack of available patches for these vulnerabilities. The most time-sensitive action is to patch or isolate vulnerable SOGo and WordPress installations, although no patches are currently available for these products.

## CVE-2026-46445: SOGo SQL Injection (risk: 70)
[P1] SOGo before 5.12.7 allows SQL injection when PostgreSQL is used, with no patch available yet. This vulnerability can be exploited for unauthorized access to sensitive data. Why now: Reported attribution (unverified): none (confidence: 0.80)

- [CVE-2026-46445](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-46445)

## CVE-2026-5361: Envira Gallery Lite XSS (risk: 60)
[P2] The Envira Gallery Lite plugin for WordPress is vulnerable to Stored Cross-Site Scripting, with no patch available. This can lead to unauthorized access and data modification. Why now: Increased exploitation of WordPress vulnerabilities (confidence: 0.70)

- [CVE-2026-5361](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-5361)
