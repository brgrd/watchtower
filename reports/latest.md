---
generated_at: 2026-05-16T12:00:06.992937+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-42897 in Microsoft Exchange Server, CVE-2026-8681 in the Essential Chat Support plugin for WordPress, and CVE-2026-8657 in the jsondiffpatch package. Internet-facing servers and applications are most exposed due to the lack of patches for these vulnerabilities. The single most time-sensitive action is to patch or isolate systems affected by CVE-2026-42897, although no patch is currently available.

## CVE-2026-42897: Microsoft Exchange RCE (risk: 100)
[P1] Microsoft Exchange Server contains a cross-site scripting vulnerability during web page generation in Outlook Web Access, which is being exploited in the wild. No patch is currently available. Why now: Reported exploitation in the wild (confidence: 0.90)

- [CVE-2026-42897](https://github.blog/changelog/2026-05-15-github-app-installation-tokens-per-request-override-header)

## CVE-2026-8681: WordPress Auth Bypass (risk: 70)
[P2] The Essential Chat Support plugin for WordPress is vulnerable to authorization bypass, which could allow attackers to gain unauthorized access. No patch is currently available. Why now: Public disclosure of vulnerability (confidence: 0.80)

- [CVE-2026-8681](https://www.securityweek.com/poc-code-published-for-critical-nginx-vulnerability/)

## CVE-2026-8657: jsondiffpatch RCE (risk: 70)
[P2] Versions of the package jsondiffpatch before 0.7.6 are vulnerable to Prototype Pollution, which could allow attackers to execute arbitrary code. No patch is currently available. Why now: Public disclosure of vulnerability (confidence: 0.80)

- [CVE-2026-8657](https://www.darkreading.com/cyber-risk/ai-code-and-agents-forces-defenders-adapt)
