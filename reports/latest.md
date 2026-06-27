---
generated_at: 2026-06-27T12:13:48.295530+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-11356 in Ivory Search, CVE-2026-13331 in Groundhogg, and CVE-2026-13335 in CodePeople Post Map. Internet-facing WordPress plugins are most exposed due to the lack of available patches for these vulnerabilities. The single most time-sensitive action is to monitor and isolate WordPress instances with the affected plugins, as no patches are currently available.

## CVE-2026-11356: Ivory Search SQLi (risk: 40)
[P2] Ivory Search WordPress plugin is vulnerable to SQL injection, allowing unauthorized data access. No patch is available, and exploitation status is unknown. Why now: Increased exploitation of WordPress plugins (confidence: 0.60)

- [NVD](https://nvd.nist.gov/v1/nvd.xhtml)

## CVE-2026-13331: Groundhogg RCE (risk: 40)
[P2] Groundhogg WordPress plugin is vulnerable to remote code execution, allowing unauthorized code execution. No patch is available, and exploitation status is unknown. Why now: Increased exploitation of WordPress plugins (confidence: 0.60)

- [NVD](https://nvd.nist.gov/v1/nvd.xhtml)

## CVE-2026-13335: CodePeople Post Map Stored XSS (risk: 40)
[P2] CodePeople Post Map WordPress plugin is vulnerable to stored cross-site scripting, allowing unauthorized code execution. No patch is available, and exploitation status is unknown. Why now: Increased exploitation of WordPress plugins (confidence: 0.60)

- [NVD](https://nvd.nist.gov/v1/nvd.xhtml)
