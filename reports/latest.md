---
generated_at: 2026-07-01T22:24:28.250155+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

CVE-2026-27435 in WofficeIO Woffice, CVE-2026-12754 in VikBooking Hotel Booking Engine & PMS, and CVE-2026-13228 in LatePoint Calendar Booking Plugin are the highest-risk items this period. Internet-facing WordPress plugins and AWS services are most exposed due to the lack of available patches for these vulnerabilities. The most time-sensitive action is to monitor and isolate systems using the affected WordPress plugins and AWS services, as no patches are currently available.

## CVE-2026-27435: WofficeIO Woffice RCE (risk: 70)
[P1] WofficeIO Woffice is vulnerable to a Missing Authorization vulnerability, allowing for remote code execution. No patch is available, and exploitation in the wild has not been reported. Why now: Lack of available patch (confidence: 0.80)

- [CVE-2026-27435](https://www.cisa.gov/news-events/alerts/2026/07/01/cisa-adds-one-known-exploited-vulnerability-catalog)

## CVE-2026-12754: VikBooking Hotel Booking Engine & PMS RCE (risk: 70)
[P1] VikBooking Hotel Booking Engine & PMS plugin for WordPress is vulnerable to a remote code execution vulnerability. No patch is available, and exploitation in the wild has not been reported. Why now: Lack of available patch (confidence: 0.80)

- [CVE-2026-12754](https://www.cisa.gov/news-events/alerts/2026/07/01/cisa-adds-one-known-exploited-vulnerability-catalog)

## CVE-2026-13228: LatePoint Calendar Booking Plugin RCE (risk: 70)
[P1] LatePoint Calendar Booking Plugin for WordPress is vulnerable to a remote code execution vulnerability. No patch is available, and exploitation in the wild has not been reported. Why now: Lack of available patch (confidence: 0.80)

- [CVE-2026-13228](https://www.cisa.gov/news-events/alerts/2026/07/01/cisa-adds-one-known-exploited-vulnerability-catalog)
