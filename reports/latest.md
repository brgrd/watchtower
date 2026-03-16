---
generated_at: 2026-03-16T22:47:00.081449+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2025-47813 in Wing FTP Server, CVE-2015-20113 in Next Click Ventures RealtyScript 4.0.2, and CVE-2013-20005 in Qool CMS 2.0 RC2. Internet-facing FTP servers and web applications are most exposed due to the lack of patches and workarounds for these vulnerabilities. The most time-sensitive action is to patch or isolate Wing FTP Server to prevent exploitation of CVE-2025-47813, although a patch is not currently available.

## Wing FTP Server Vuln (risk: 100)
[P1] Wing FTP Server contains a generation of error message containing sensitive information vulnerability, which is being exploited in the wild. No patch or workaround is available. Why now: This vulnerability is being actively exploited in the wild. (confidence: 0.90)

- [CVE-2025-47813](https://www.cve.org/CVERecord?id=CVE-2025-47813)

## Next Click Ventures RealtyScript Vuln (risk: 70)
[P2] Next Click Ventures RealtyScript 4.0.2 contains multiple vulnerabilities, including cross-site request forgery and cross-site scripting. No patch or workaround is available. Why now: These vulnerabilities can be exploited to gain unauthorized access to sensitive data. (confidence: 0.70)

- [CVE-2015-20113](https://www.cve.org/CVERecord?id=CVE-2015-20113)

## Qool CMS Vuln (risk: 60)
[P3] Qool CMS 2.0 RC2 contains a cross-site request forgery vulnerability, which can be exploited to gain unauthorized access to sensitive data. No patch or workaround is available. Why now: This vulnerability can be exploited to gain unauthorized access to sensitive data. (confidence: 0.50)

- [CVE-2013-20005](https://www.cve.org/CVERecord?id=CVE-2013-20005)
