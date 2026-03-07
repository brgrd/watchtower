---
generated_at: 2026-03-07T05:47:30.600145+00:00
model: meta-llama/llama-4-scout-17b-16e-instruct
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period include CVE-2026-1981 in the HUMN-1 AI Website Scanner & Human Certification by Winston AI plugin for WordPress, CVE-2026-25071 in XikeStor SKS8310-8X Network Switch firmware versions 1.04.B07 and prior, and CVE-2026-1644 in the WP Frontend Profile plugin for WordPress. Internet-facing WordPress plugins and XikeStor network switches are most exposed due to their vulnerability to SQL injection, cross-site request forgery, and other attacks, with many lacking patches. The most time-sensitive action is to patch the WP Frontend Profile plugin for WordPress vulnerable to Cross-Site Request Forgery (CVE-2026-1644).

## CVE-2026-1644 in WP Frontend Profile (risk: 70)
[P1] The WP Frontend Profile plugin for WordPress is vulnerable to Cross-Site Request Forgery, with a patch available. Why now: High-risk vulnerability in popular WordPress plugin, patch available (confidence: 0.90)


## CVE-2026-2429 in Community Events plugin (risk: 60)
[P1] The Community Events plugin for WordPress is vulnerable to SQL Injection, with a patch available. Why now: High-risk vulnerability in popular WordPress plugin, patch available (confidence: 0.80)


## CVE-2026-1981 in Winston AI plugin (risk: 40)
[P2] The HUMN-1 AI Website Scanner & Human Certification by Winston AI plugin for WordPress is vulnerable, with no patch available. Why now: Newly disclosed vulnerability in popular WordPress plugin (confidence: 0.80)


## CVE-2026-25071 in XikeStor SKS8310-8X (risk: 40)
[P2] XikeStor SKS8310-8X Network Switch firmware versions 1.04.B07 and prior are vulnerable, with no patch available. Why now: Newly disclosed vulnerability in network switch firmware (confidence: 0.70)


## CVE-2026-2371 in Greenshift plugin (risk: 40)
[P2] The Greenshift – animation and page builder blocks plugin for WordPress is vulnerable, with no patch available. Why now: Newly disclosed vulnerability in popular WordPress plugin (confidence: 0.60)


## CVE-2026-2020 in JS Archive List plugin (risk: 40)
[P2] The JS Archive List plugin for WordPress is vulnerable to PHP Object Injection, with no patch available. Why now: Newly disclosed vulnerability in popular WordPress plugin (confidence: 0.70)

