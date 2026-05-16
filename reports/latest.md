---
generated_at: 2026-05-16T10:23:20.850849+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-42897 in Microsoft Exchange Server, CVE-2026-8704 in Crypt::DSA, and CVE-2026-8681 in the Essential Chat Support plugin for WordPress. Internet-facing email servers and web applications are most exposed due to the lack of patches for these vulnerabilities. The most time-sensitive action is to patch or isolate Microsoft Exchange Server to prevent exploitation of CVE-2026-42897, although no patch is currently available.

## CVE-2026-42897: Microsoft Exchange RCE (risk: 100)
[P1] Microsoft Exchange Server contains a cross-site scripting vulnerability during web page generation in Outlook Web Access, which is being exploited in the wild. No patch is currently available. Why now: Reported exploitation in the wild (confidence: 0.90)

- [CVE-2026-42897](https://github.blog/changelog/2026-05-15-github-app-installation-tokens-per-request-override-header)

## CVE-2026-8704: Crypt::DSA Code Execution (risk: 70)
[P2] Crypt::DSA versions through 1.19 for Perl use 2-args open, allowing existing file overwrite. No patch is currently available. Why now: Lack of patch and potential for exploitation (confidence: 0.80)

- [CVE-2026-8704](https://www.securityweek.com/poc-code-published-for-critical-nginx-vulnerability/)
