---
generated_at: 2026-06-04T12:10:55.360407+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-22054 in Active IQ Config Advisor, CVE-2026-10775 in sgl-project SGLang, and CVE-2026-45247 in Magento. Internet-facing systems, such as web servers and VPN appliances, are most exposed due to the lack of available patches for these vulnerabilities. The single most time-sensitive action is to monitor for potential exploitation of these vulnerabilities, particularly in systems using Active IQ Config Advisor and Magento, as no patches are currently available.

## CVE-2026-45247: Magento RCE Flaw (risk: 100)
[P1] CISA added a critical flaw impacting Mirasvit Cache Warmer, a popular Magento full-page cache extension, to its KEV catalog. No patch is currently available, and exploitation in the wild has been reported. Why now: Reported exploitation in the wild (confidence: 0.90)

- [CISA Adds Exploited Magento RCE Flaw CVE-2026-45247 to KEV Catalog](https://thehackernews.com/2026/06/cisa-adds-exploited-magento-rce-flaw.html)

## CVE-2026-22054: Active IQ Config Advisor RCE (risk: 70)
[P1] Active IQ Config Advisor version 6.7.3 contains hard-coded credentials that could allow for remote code execution. No patch is currently available, and exploitation in the wild has not been reported. Why now: Reported attribution (unverified): none (confidence: 0.80)

- [CVE-2026-22054](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-22054)

## CVE-2026-10775: sgl-project SGLang Vulnerability (risk: 70)
[P2] A vulnerability was determined in sgl-project SGLang up to 0.5.11. No patch is currently available, and exploitation in the wild has not been reported. Why now: Newly reported vulnerability (confidence: 0.70)

- [CVE-2026-10775](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-10775)
