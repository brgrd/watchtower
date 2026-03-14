---
generated_at: 2026-03-14T16:45:27.823240+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-3910 in Google Chromium V8, CVE-2026-3909 in Google Skia, and CVE-2025-12455 in OpenText Vertica. Internet-facing systems and web applications are most exposed due to the lack of patches for these vulnerabilities, which are being actively exploited in the wild. The most time-sensitive action is to patch or isolate systems running Google Chromium V8 and Google Skia, although patches are not currently available, and to monitor for suspicious activity related to these vulnerabilities.

## Google Chromium V8 RCE (risk: 100)
[P1] CVE-2026-3910 is a memory buffer vulnerability in Google Chromium V8 that can be exploited for remote code execution, and it is being actively exploited in the wild. No patch is currently available. Why now: Active exploitation in the wild (confidence: 0.90)

- [CVE-2026-3910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-3910)

## Google Skia OOB Write (risk: 100)
[P1] CVE-2026-3909 is an out-of-bounds write vulnerability in Google Skia that can be exploited for remote code execution, and it is being actively exploited in the wild. No patch is currently available. Why now: Active exploitation in the wild (confidence: 0.90)

- [CVE-2026-3909](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-3909)

## OpenText Vertica Auth Bypass (risk: 70)
[P2] CVE-2025-12455 is an authentication bypass vulnerability in OpenText Vertica that can be exploited for unauthorized access. No patch is currently available. Why now: Lack of patch (confidence: 0.60)

- [CVE-2025-12455](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-12455)
