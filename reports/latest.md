---
generated_at: 2026-07-16T22:11:26.952578+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-58644 in Microsoft SharePoint, CVE-2026-22752 in Spring Security, and CVE-2026-35146 in HCL DFXServer. Internet-facing servers and applications are most exposed due to the lack of patches for these vulnerabilities. The most time-sensitive action is to patch or isolate systems affected by CVE-2026-58644, as it is being exploited in the wild and no patch is currently available.

## CVE-2026-58644: Microsoft SharePoint RCE (risk: 100)
[P1] Microsoft SharePoint contains a deserialization of untrusted data vulnerability that allows an unauthorized attacker to execute arbitrary code. This vulnerability is being exploited in the wild and no patch is currently available. Why now: Reported exploitation in the wild (confidence: 0.90)

- [CISA Adds Three Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/07/16/cisa-adds-three-known-exploited-vulnerabilities-catalog)

## CVE-2026-22752: Spring Security Auth Bypass (risk: 70)
[P2] Spring Security contains an authentication bypass vulnerability that allows an unauthorized attacker to access sensitive data. This vulnerability is not being exploited in the wild and no patch is currently available. Why now: Newly disclosed vulnerability (confidence: 0.80)

- [CVE-2026-22752](https://nvd.nist.gov/v1/nvd.xhtml?nvd.nist.gov/nvd/cve-2026-22752)

## CVE-2026-35146: HCL DFXServer Unencrypted Communication (risk: 60)
[P3] HCL DFXServer contains an unencrypted communication vulnerability that allows an unauthorized attacker to intercept sensitive data. This vulnerability is not being exploited in the wild and no patch is currently available. Why now: Newly disclosed vulnerability (confidence: 0.70)

- [HCL DFXServer Unencrypted Communication Vulnerability](https://www.hcltech.com/cve-2026-35146)
