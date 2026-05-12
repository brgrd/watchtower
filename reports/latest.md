---
generated_at: 2026-05-12T22:20:30.682651+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-45185 in Exim, ABB AC500 V3 Multiple Vulnerabilities, and GCP-2026-026. Internet-facing mail servers and industrial control systems are most exposed due to the lack of patches for these vulnerabilities. The most time-sensitive action is to patch Exim to version 4.99.3 or later, although no patch is currently available for CVE-2026-45185.

## CVE-2026-45185: Exim RCE (risk: 70)
[P1] Exim before 4.99.3 has a remotely reachable vulnerability in certain GnuTLS configurations, allowing arbitrary code execution. No patch is currently available, and there is no evidence of exploitation in the wild. Why now: Reported attribution (unverified): none (confidence: 0.80)

- [CVE-2026-45185](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-03)
