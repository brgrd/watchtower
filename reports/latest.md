---
generated_at: 2026-07-29T23:07:33.309924+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-12895 in Frappe's ERPNext, CVE-2026-18220 in the BFD library's DLX ELF back, and CVE-2026-14488 in the Meta Box AIO plugin for WordPress. These vulnerabilities expose internet-facing web applications, particularly those using WordPress plugins, to potential SQL injection and out-of-bounds write attacks. The most time-sensitive action is to patch or isolate affected systems, specifically updating Frappe's ERPNext to a version newer than 15.107.0 and Frappe 15.107.2, as no patches are currently available for these vulnerabilities.

## CVE-2026-12895: Frappe ERPNext SQL Injection (risk: 70)
[P1] Frappe's ERPNext versions 15.107.0 and Frappe 15.107.2 are vulnerable to SQL injection, allowing attackers to execute arbitrary SQL code. No patch is currently available. Why now: High-risk vulnerability with potential for significant impact. (confidence: 0.90)

- [CVE-2026-12895](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-12895)

## CVE-2026-18220: BFD Library Out-of-Bounds Write (risk: 70)
[P1] The BFD library's DLX ELF back is vulnerable to an out-of-bounds write, allowing attackers to execute arbitrary code. No patch is currently available. Why now: High-risk vulnerability with potential for significant impact. (confidence: 0.90)

- [CVE-2026-18220](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-18220)

## CVE-2026-14488: Meta Box AIO Plugin Vulnerability (risk: 60)
[P2] The Meta Box AIO plugin for WordPress is vulnerable to missing authorization, allowing attackers to access sensitive data. No patch is currently available. Why now: Medium-risk vulnerability with potential for significant impact. (confidence: 0.80)

- [CVE-2026-14488](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-14488)
