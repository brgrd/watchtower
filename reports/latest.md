---
generated_at: 2026-03-14T04:50:33.230088+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-3910 in Google Chromium V8, CVE-2025-12455 in OpenText Vertica, and CVE-2025-13702 in IBM Sterling Partner Engagement Manager. Internet-facing systems, particularly those using Google Chrome, are most exposed due to the lack of available patches for these vulnerabilities. The most time-sensitive action is to patch or isolate systems using Google Chrome, as a patch is not currently available for CVE-2026-3910.

## Chrome V8 Vulnerability (risk: 100)
[P1] CVE-2026-3910 is a memory buffer vulnerability in Google Chromium V8 that is being exploited in the wild, with no available patch. This vulnerability affects all systems using Google Chrome. Why now: Reported exploitation in the wild without a available patch. (confidence: 0.90)

- [Google Fixes Two Chrome Zero-Days Exploited in the Wild Affecting Skia and V8](https://thehackernews.com/2026/03/google-fixes-two-chrome-zero-days.html)

## OpenText Vertica Vulnerability (risk: 70)
[P2] CVE-2025-12455 is an observable response discrepancy vulnerability in OpenText Vertica, with no available patch. This vulnerability affects systems using OpenText Vertica. Why now: Lack of available patch for this vulnerability. (confidence: 0.60)

- [Observable response discrepancy vulnerability in OpenText Vertica](https://nvd.nist.gov/v1/nvdidata.feeds/nvdwebdata.json)

## IBM Sterling Partner Engagement Manager Vulnerability (risk: 70)
[P2] CVE-2025-13702 is a vulnerability in IBM Sterling Partner Engagement Manager, with no available patch. This vulnerability affects systems using IBM Sterling Partner Engagement Manager. Why now: Lack of available patch for this vulnerability. (confidence: 0.60)

- [IBM Sterling Partner Engagement Manager 6.2.3.0 through 6.2.3.5 and 6.2.4.0 through 6.2.4.5](https://nvd.nist.gov/v1/nvdidata.feeds/nvdwebdata.json)
