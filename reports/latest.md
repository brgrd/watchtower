---
generated_at: 2026-06-21T21:24:44.738811+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

CVE-2026-12799, CVE-2026-12797, and CVE-2026-12798 in BerriAI litellm represent the highest-risk items this period. Internet-facing applications and container orchestration nodes are most exposed due to the lack of available patches for these vulnerabilities. The most time-sensitive action is to monitor and isolate BerriAI litellm versions up to 1.82.2, as no patches are currently available.

## CVE-2026-12799: BerriAI LiteLLM RCE (risk: 70)
[P1] A security vulnerability in BerriAI litellm up to 1.82.2 allows for arbitrary code execution. No patch is currently available. Why now: Lack of available patches increases the risk of exploitation. (confidence: 0.80)

- [CVE-2026-12799](https://nvd.nist.gov/v1/nvd.xhtml?nvd.nist.gov/v1/nvd.xhtml)

## CVE-2026-12797: BerriAI LiteLLM Privilege Escalation (risk: 60)
[P2] A security flaw in BerriAI litellm up to 1.82.5 allows for privilege escalation. No patch is currently available. Why now: Lack of available patches increases the risk of exploitation. (confidence: 0.70)

- [CVE-2026-12797](https://nvd.nist.gov/v1/nvd.xhtml?nvd.nist.gov/v1/nvd.xhtml)
