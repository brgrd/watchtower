---
generated_at: 2026-08-01T22:07:53.693716+00:00
model: llama-3.3-70b-versatile
project: Watchtower
---
# Watchtower — Infrastructure Security Briefing

## Analyst Summary

The highest-risk items this period are CVE-2026-10773 in the DHCPv4 client helper, CVE-2025-71404 in better-auth versions, and CVE-2026-66401 in FreeRDP. Internet-facing systems, particularly those using affected versions of FreeRDP and better-auth, are most exposed due to the lack of available patches and potential for exploitation. The most time-sensitive action is to monitor and isolate systems using FreeRDP before version 3.29.0, as no patch is currently available.

## CVE-2026-10773: DHCPv4 Client Helper RCE (risk: 40)
[P2] The DHCPv4 client helper net_dhcpv4_msg_type_name() contains a vulnerability, but no patch or exploit is currently available. Affected systems should be monitored for potential exploitation. Why now: Newly disclosed vulnerability with potential for exploitation. (confidence: 0.60)

- [CVE-2026-10773](https://nvd.nist.gov/v1/nvd.xhtml?nvd.nist.gov/v1/nvd.xhtml?cve.id=CVE-2026-10773)

## CVE-2025-71404: better-auth Reflected Cross-Site Scripting (risk: 40)
[P2] better-auth versions after v0.0.2 and before 1.1.16 contain a reflected cross-site scripting vulnerability, but no patch or exploit is currently available. Affected systems should be monitored for potential exploitation. Why now: Newly disclosed vulnerability with potential for exploitation. (confidence: 0.60)

- [CVE-2025-71404](https://nvd.nist.gov/v1/nvd.xhtml?nvd.nist.gov/v1/nvd.xhtml?cve.id=CVE-2025-71404)

## CVE-2026-66401: FreeRDP Out-of-Bounds Heap Read (risk: 40)
[P1] FreeRDP before 3.29.0 contains an out-of-bounds heap read vulnerability, but no patch is currently available. Affected systems should be monitored and isolated to prevent potential exploitation. Why now: Newly disclosed vulnerability with potential for exploitation and no available patch. (confidence: 0.80)

- [CVE-2026-66401](https://nvd.nist.gov/v1/nvd.xhtml?nvd.nist.gov/v1/nvd.xhtml?cve.id=CVE-2026-66401)
