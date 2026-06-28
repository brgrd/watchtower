---
generated_at: 2026-06-28T11:54:56.890537+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-10643 in Zephyr's IP socket recvmsg() implementation, CVE-2026-58050 in libssh2, and CVE-2026-8095 in the Frontend File Manager Plugin for WordPress. Internet-facing systems, particularly those using Zephyr and libssh2, are most exposed due to the lack of available patches for these vulnerabilities. The most time-sensitive action is to monitor and isolate systems using the affected Zephyr and libssh2 versions, as no patches are currently available.

## CVE-2026-10643: Zephyr IP Socket Recvmsg RCE (risk: 70)
[P1] Zephyr's IP socket recvmsg() implementation is vulnerable to arbitrary code execution, with no patch available. This affects Zephyr-based systems, particularly those exposed to the internet. Why now: Lack of patch availability increases the urgency to address this vulnerability. (confidence: 0.80)

- [NVD CVE-2026-10643](https://nvd.nist.gov/v1/cve/2026-10643)

## CVE-2026-58050: libssh2 Public Key List Vulnerability (risk: 70)
[P1] libssh2 through 1.11.1 has a vulnerability in its public key list handling, with no patch available. This affects systems using libssh2 for secure connections. Why now: The lack of a patch for this vulnerability in libssh2 increases the risk for systems relying on it for secure connections. (confidence: 0.80)

- [NVD CVE-2026-58050](https://nvd.nist.gov/v1/cve/2026-58050)

## CVE-2026-8095: WordPress Frontend File Manager Plugin Vulnerability (risk: 70)
[P1] The Frontend File Manager Plugin for WordPress is vulnerable to authentication bypass, with no patch available. This affects WordPress sites using this plugin. Why now: The lack of a patch for this vulnerability in the Frontend File Manager Plugin increases the risk for WordPress sites using it. (confidence: 0.80)

- [NVD CVE-2026-8095](https://nvd.nist.gov/v1/cve/2026-8095)
