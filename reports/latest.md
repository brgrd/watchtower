---
generated_at: 2026-05-27T22:04:45.738723+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-2280 in the rexCrawler plugin for WordPress, CVE-2026-3348 in the MinhNhut Link Gateway plugin for WordPress, and CVE-2026-42727 in WP Wham Checkout. These vulnerabilities expose internet-facing web applications, particularly those using WordPress plugins, to stored cross-site scripting and SQL injection attacks. The single most time-sensitive action is to patch or isolate vulnerable WordPress plugins, specifically rexCrawler and MinhNhut Link Gateway, although no patches are currently available.

## CVE-2026-2280: rexCrawler SQL Injection (risk: 70)
[P1] The rexCrawler plugin for WordPress is vulnerable to stored cross-site scripting, allowing attackers to inject malicious code. No patch is currently available. Why now: Reported vulnerability in widely used WordPress plugin (confidence: 0.80)

- [CVE-2026-2280](https://www.cisa.gov/news-events/alerts/2026/05/27/cisa-adds-three-known-exploited-vulnerabilities-catalog)

## CVE-2026-3348: MinhNhut Link Gateway SQL Injection (risk: 70)
[P1] The MinhNhut Link Gateway plugin for WordPress is vulnerable to stored cross-site scripting, allowing attackers to inject malicious code. No patch is currently available. Why now: Reported vulnerability in widely used WordPress plugin (confidence: 0.80)

- [CVE-2026-3348](https://www.cisa.gov/news-events/alerts/2026/05/27/cisa-adds-three-known-exploited-vulnerabilities-catalog)

## CVE-2026-42727: WP Wham Checkout SQL Injection (risk: 70)
[P1] WP Wham Checkout is vulnerable to SQL injection, allowing attackers to inject malicious code. No patch is currently available. Why now: Reported vulnerability in widely used e-commerce plugin (confidence: 0.80)

- [CVE-2026-42727](https://www.cisa.gov/news-events/alerts/2026/05/27/cisa-adds-three-known-exploited-vulnerabilities-catalog)
