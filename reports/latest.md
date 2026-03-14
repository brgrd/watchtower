---
generated_at: 2026-03-14T22:38:16.753987+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-3909 in Google Skia and CVE-2026-3910 in Google Chromium V8, which are being actively exploited in the wild. Internet-facing systems and applications that utilize these vulnerable components are most exposed, particularly those that have not applied workarounds or patches, which are currently unavailable. The most time-sensitive action is to monitor and isolate systems using Google Skia and Google Chromium V8, as patches are not currently available for these vulnerabilities.

## Google Skia OOB Write (risk: 70)
[P1] CVE-2026-3909 is an out-of-bounds write vulnerability in Google Skia that could allow a remote attacker to perform out of bounds memory access, and is being actively exploited in the wild. No patch or workaround is currently available. Why now: Reported exploitation in the wild (confidence: 0.80)

- [CVE-2026-3909](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-3909)

## Google Chromium V8 Memory Buffer Vulnerability (risk: 70)
[P1] CVE-2026-3910 is an improper restriction of operations within the bounds of a memory buffer vulnerability in Google Chromium V8, which could allow a remote attacker to execute arbitrary code, and is being actively exploited in the wild. No patch or workaround is currently available. Why now: Reported exploitation in the wild (confidence: 0.80)

- [CVE-2026-3910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-3910)

## GlassWorm Supply-Chain Attack (risk: 60)
[P2] The GlassWorm supply-chain attack is abusing 72 Open VSX extensions to target developers, and could enable prompt injection and data exfiltration. The attack is ongoing and has been reported to be actively exploiting vulnerabilities in the wild. Why now: Reported attribution (unverified): unknown (confidence: 0.60)

- [GlassWorm Supply-Chain Attack Abuses 72 Open VSX Extensions to Target Developers](https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html)
