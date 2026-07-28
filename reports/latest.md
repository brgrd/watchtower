---
generated_at: 2026-07-28T12:04:52.441362+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-17528 in nice-select2, CVE-2026-17524 in zip-lib, and CVE-2026-14821 in Quiz and Survey Master WordPress plugin. Internet-facing web applications and WordPress plugins are most exposed due to the lack of patches for these vulnerabilities. The most time-sensitive action is to patch or isolate systems using the affected WordPress plugins, specifically Quiz and Survey Master and Event Tickets and Registration, although no patches are currently available.

## CVE-2026-14821: Quiz and Survey Master WordPress plugin RCE (risk: 80)
[P1] The Quiz and Survey Master WordPress plugin before 11.1.5 does not perform proper validation, and there is no patch available. This vulnerability can be exploited to gain remote code execution. Why now: Lack of patch and potential for remote code execution (confidence: 0.90)

- [CVE-2026-14821](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-14821)

## CVE-2026-17528: nice-select2 RCE (risk: 70)
[P1] Versions of nice-select2 before 2.4.1 are vulnerable to Cross-site scripting, and there is no patch available. This vulnerability can be exploited to gain remote code execution. Why now: Lack of patch and potential for remote code execution (confidence: 0.80)

- [CVE-2026-17528](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-17528)

## CVE-2026-17524: zip-lib Directory Traversal (risk: 60)
[P2] Versions of zip-lib before 1.1.0 are vulnerable to Directory Traversal, and there is no patch available. This vulnerability can be exploited to read or write files on the system. Why now: Lack of patch and potential for file system access (confidence: 0.70)

- [CVE-2026-17524](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-17524)
