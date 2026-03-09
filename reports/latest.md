---
generated_at: 2026-03-09T22:40:30.854530+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

CVE-2025-26399 in SolarWinds Web Help Desk, CVE-2021-22054 in Omnissa Workspace One UEM, and CVE-2026-1603 in Ivanti Endpoint Manager represent the highest-risk items this period due to their exploitation in the wild. Internet-facing systems, particularly those with unpatched SolarWinds and Ivanti Endpoint Manager installations, are most exposed right now because they lack available patches and have known active exploitation. The single most time-sensitive action is to isolate or patch SolarWinds Web Help Desk and Ivanti Endpoint Manager, although no patches are currently available for these products.

## SolarWinds Deserialization Vuln (risk: 100)
[P1] SolarWinds Web Help Desk contains a deserialization of untrusted data vulnerability, actively exploited in the wild with no available patch. This vulnerability poses a significant risk to internet-facing systems. Why now: Active exploitation in the wild (confidence: 0.90)

- [CVE-2025-26399](https://www.cisa.gov/known-exploited-vulnerabilities)

## Omnissa Workspace One UEM SSRF (risk: 100)
[P1] Omnissa Workspace One UEM contains a server-side request forgery vulnerability, exploited in the wild with no available patch. This vulnerability poses a risk to internal systems. Why now: Active exploitation in the wild (confidence: 0.90)

- [CVE-2021-22054](https://www.cisa.gov/known-exploited-vulnerabilities)

## Ivanti Endpoint Manager Auth Bypass (risk: 100)
[P1] Ivanti Endpoint Manager contains an authentication bypass vulnerability, exploited in the wild with no available patch. This vulnerability poses a significant risk to internal systems. Why now: Active exploitation in the wild (confidence: 0.90)

- [CVE-2026-1603](https://www.cisa.gov/known-exploited-vulnerabilities)
