---
generated_at: 2026-05-23T09:13:53.266446+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-48172 in LiteSpeed cPanel Plugin, CVE-2026-9255 in Kiro CLI, and CVE-2026-9291 in Amazon Braket SDK. Internet-facing systems and cloud services are most exposed due to the active exploitation of these vulnerabilities in the wild. The most time-sensitive action is to patch or isolate systems affected by CVE-2026-48172, as it allows arbitrary script execution as root, and a patch is available for LiteSpeed cPanel Plugin versions prior to the fixed version.

## CVE-2026-48172: LiteSpeed cPanel (risk: 100)
[P1] LiteSpeed cPanel Plugin contains a vulnerability that allows arbitrary script execution as root, and it is being actively exploited in the wild. A patch is available for versions prior to the fixed version. Why now: Reported attribution (unverified): none, but active exploitation in the wild (confidence: 0.90)

- [LiteSpeed cPanel Plugin CVE-2026-48172 Exploited to Run Scripts as Root](https://thehackernews.com/2026/05/litespeed-cpanel-plugin-cve-2026-48172.html)

## CVE-2026-9255: Kiro CLI (risk: 100)
[P1] Kiro CLI contains a vulnerability that allows tool execution without authorization via piped stdin, and it is being actively exploited in the wild. A patch is available for Kiro CLI versions prior to 1.2. Why now: Active exploitation in the wild (confidence: 0.90)

- [CVE-2026-9255 - Tool Execution Without Authorization via Piped Stdin in Kiro CLI](https://aws.amazon.com/security/security-bulletins/rss/2026-035-aws/)

## CVE-2026-9291: Amazon Braket SDK (risk: 100)
[P1] Amazon Braket SDK contains an insecure deserialization vulnerability in job results processing, and it is being actively exploited in the wild. A patch is available for Amazon Braket SDK versions prior to the fixed version. Why now: Active exploitation in the wild (confidence: 0.90)

- [CVE-2026-9291 - Insecure Deserialization in Amazon Braket SDK Job Results Processing](https://aws.amazon.com/security/security-bulletins/rss/2026-036-aws/)
