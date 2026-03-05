"""
Mock report generator — populates all UI components with synthetic data.
Run from the workspace root:
    python scripts/mock_report.py
Output: reports/index.html
"""

import sys, os, datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.makedirs("reports", exist_ok=True)

from agent.runner import _write_index_html

# ---------------------------------------------------------------------------
# Synthetic findings (cards)
# Each card mirrors what the LLM pipeline produces.
# ---------------------------------------------------------------------------
MOCK_CARDS = [
    # ── P1 / Critical ────────────────────────────────────────────────────────
    {
        "title": "CVE-2026-1001 — Critical RCE in OpenSSL 3.x (actively exploited in the wild)",
        "risk_score": 97,
        "priority": "P1",
        "domains": ["crypto_lib", "os_kernel", "web_framework"],
        "summary": (
            "A heap buffer-overflow in OpenSSL 3.0–3.3 allows remote code execution via "
            "malformed TLS ClientHello packets. PoC circulating on GitHub; ransomware actors "
            "scanning en masse within 6 hours of disclosure."
        ),
        "why_now": "Active exploitation confirmed by CISA KEV and multiple threat-intel vendors.",
        "confidence": 0.97,
        "recommended_actions_24h": [
            "Patch OpenSSL to 3.3.2+ on all hosts.",
            "Block inbound TLS from untrusted CIDRs at perimeter.",
            "Enable WAF rule set for CVE-2026-1001.",
        ],
        "recommended_actions_7d": [
            "Complete inventory of all services linking libssl.",
            "Rotate TLS certificates on externally facing endpoints.",
            "Review EDR telemetry for suspicious OpenSSL process chains.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://www.openssl.org/news/secadv/20260115.txt",
                    "title": "OpenSSL Security Advisory",
                },
                {
                    "url": "https://www.bleepingcomputer.com/news/security/cve-2026-1001-rce/",
                    "title": "BleepingComputer — OpenSSL RCE",
                },
            ]
        },
    },
    {
        "title": "npm supply-chain attack: 'colors-pro' package exfiltrates AWS credentials",
        "risk_score": 92,
        "priority": "P1",
        "domains": ["supply_chain", "pkg_npm", "cloud_iam"],
        "summary": (
            "Typosquat package 'colors-pro' (47k weekly downloads) contains obfuscated "
            "postinstall hook that reads ~/.aws/credentials and sends them to attacker-controlled "
            "C2. GitHub Advisory Database entry published."
        ),
        "why_now": "Package has been live for 9 days; downloads still rising.",
        "confidence": 0.94,
        "recommended_actions_24h": [
            "Remove colors-pro from all package.json files immediately.",
            "Rotate any AWS keys present on affected developer workstations.",
            "Search SIEM for outbound requests to attacker C2 domain (colrs-cdn[.]io).",
        ],
        "recommended_actions_7d": [
            "Enable npm audit gates in CI/CD.",
            "Implement dependency pinning with lockfile verification.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://github.com/advisories/GHSA-xxxx-npm-colorspro",
                    "title": "GitHub Security Advisory",
                },
                {
                    "url": "https://snyk.io/blog/colors-pro-supply-chain/",
                    "title": "Snyk Blog",
                },
            ]
        },
    },
    {
        "title": "Okta zero-day: session token forgery via SAML assertion bypass",
        "risk_score": 91,
        "priority": "P1",
        "domains": ["identity", "cloud_iam", "ca_trust"],
        "summary": (
            "Attackers can craft a malformed SAML assertion that Okta's SP validates as "
            "legitimate, issuing a session token for any target user. Impacts all Okta "
            "Classic Engine tenants running < 2026.01.3."
        ),
        "why_now": "Three enterprise tenants breached in the last 48 hours per Okta's incident notice.",
        "confidence": 0.96,
        "recommended_actions_24h": [
            "Apply Okta hotfix 2026.01.3 or enable temporary SAML signature enforcement workaround.",
            "Audit recent SSO login events for anomalous source IPs.",
            "Revoke and re-issue all active admin sessions.",
        ],
        "recommended_actions_7d": [
            "Enable FIDO2/WebAuthn for all privileged accounts.",
            "Review SAML IdP configuration for signature enforcement settings.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://trust.okta.com/security-advisories/2026-001",
                    "title": "Okta Security Advisory 2026-001",
                },
                {
                    "url": "https://www.therecord.media/okta-zero-day-saml/",
                    "title": "The Record — Okta Zero-Day",
                },
            ]
        },
    },
    {
        "title": "Linux kernel 6.x — local privilege escalation via io_uring race condition (known exploited)",
        "risk_score": 89,
        "priority": "P1",
        "domains": ["os_kernel", "container"],
        "summary": (
            "A race condition in the io_uring subsystem allows unprivileged local users to "
            "escalate to root. Exploitation via container escape confirmed on GKE, EKS, and "
            "AKS. CVE-2026-2200 assigned."
        ),
        "why_now": "Public PoC available; container escape path confirmed by multiple cloud vendors.",
        "confidence": 0.93,
        "recommended_actions_24h": [
            "Apply kernel patch 6.6.22+ or disable io_uring via sysctl.",
            "Restrict io_uring in container runtime (seccomp/AppArmor).",
        ],
        "recommended_actions_7d": [
            "Upgrade all node pools to patched AMIs.",
            "Review container pod-security policies for privileged escalation paths.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://lore.kernel.org/linux-security-module/2026/iouring-cve",
                    "title": "Kernel Mailing List",
                },
                {
                    "url": "https://security.googleblog.com/2026/01/gke-io-uring-cve.html",
                    "title": "Google Security Blog",
                },
            ]
        },
    },
    # ── P1 / High ────────────────────────────────────────────────────────────
    {
        "title": "PyPI malware: 'requests-async2' steals private keys from CI environments",
        "risk_score": 86,
        "priority": "P1",
        "domains": ["pkg_pypi", "supply_chain"],
        "summary": (
            "Malicious PyPI package requests-async2 scans for SSH private keys and GitHub "
            "tokens during import. 12,000 downloads recorded before takedown."
        ),
        "why_now": "Package indexed by Google and cached by many build tools; stale installs persist.",
        "confidence": 0.91,
        "recommended_actions_24h": [
            "Remove requests-async2 from all virtual environments and lock files.",
            "Rotate SSH keys and GitHub PATs on any host that installed the package.",
        ],
        "recommended_actions_7d": [
            "Add requests-async2 to internal blocklist.",
            "Enable pypi-scan pre-install hooks in pipelines.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://blog.reversinglabs.com/requests-async2-malware",
                    "title": "ReversingLabs Analysis",
                },
                {
                    "url": "https://www.bleepingcomputer.com/news/security/pypi-malware-keys/",
                    "title": "BleepingComputer",
                },
            ]
        },
    },
    # ── P2 / High ────────────────────────────────────────────────────────────
    {
        "title": "GitHub Actions runner compromise via poisoned workflow cache",
        "risk_score": 78,
        "priority": "P2",
        "domains": ["supply_chain", "cloud_iam", "container"],
        "summary": (
            "Researchers demonstrate persistent GHES runner compromise by poisoning the "
            "actions/cache step. Attacker-controlled artifacts injected into subsequent "
            "release builds without triggering workflow diff alerts."
        ),
        "why_now": "Technique published with working PoC; confirmed against 3 OSS projects.",
        "confidence": 0.82,
        "recommended_actions_24h": [
            "Pin all third-party Action versions to full SHA references.",
            "Review cache key namespaces for cross-PR pollution vectors.",
        ],
        "recommended_actions_7d": [
            "Enable branch protection rules on all GitHub Actions workflows.",
            "Audit CODEOWNERS for Actions workflow file ownership.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://unit42.paloaltonetworks.com/github-actions-cache-poisoning/",
                    "title": "Unit 42 — Cache Poisoning",
                },
            ]
        },
    },
    {
        "title": "Apache Tomcat 10.x — partial request smuggling via chunked encoding",
        "risk_score": 74,
        "priority": "P2",
        "domains": ["web_framework", "container"],
        "summary": (
            "A flaw in Tomcat's chunked-encoding parser allows crafted requests to bypass "
            "access controls and reach internal endpoints not exposed at the edge."
        ),
        "why_now": "CVSS 8.1; patch released; active scanning for vulnerable endpoints observed.",
        "confidence": 0.79,
        "recommended_actions_24h": [
            "Upgrade Tomcat to 10.1.28+.",
            "Enable strict HTTP/1.1 chunked-encoding validation at reverse proxy.",
        ],
        "recommended_actions_7d": [
            "Audit access-control configurations on internal Tomcat instances.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://tomcat.apache.org/security-10.html#fixed-in-apache-tomcat-10.1.28",
                    "title": "Apache Tomcat Security",
                },
                {
                    "url": "https://portswigger.net/research/tomcat-smuggling-2026",
                    "title": "PortSwigger Research",
                },
            ]
        },
    },
    {
        "title": "AWS IAM confused-deputy via Lambda URL resource-based policies",
        "risk_score": 71,
        "priority": "P2",
        "domains": ["cloud_iam", "identity"],
        "summary": (
            "Misconfigured Lambda function URL policies combined with cross-account assume-role "
            "chains enable confused-deputy attacks, allowing lateral movement between AWS "
            "accounts without explicit cross-account trust grants."
        ),
        "why_now": "New Terraform module published that defaults to vulnerable policy pattern.",
        "confidence": 0.76,
        "recommended_actions_24h": [
            "Audit Lambda function URL auth configurations for aws:SourceAccount conditions.",
        ],
        "recommended_actions_7d": [
            "Apply SCPs restricting Lambda URL creation without mandatory source-account condition.",
            "Update Terraform module to patched version with aws:SourceAccount enforcement.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://unit42.paloaltonetworks.com/aws-lambda-confused-deputy/",
                    "title": "Unit 42 — AWS Confused Deputy",
                },
                {
                    "url": "https://www.darkreading.com/cloud-security/aws-iam-lambda-vuln",
                    "title": "Dark Reading",
                },
            ]
        },
    },
    {
        "title": "Let's Encrypt intermediate CA rotation — misissuance risk window",
        "risk_score": 68,
        "priority": "P2",
        "domains": ["ca_trust", "identity"],
        "summary": (
            "Let's Encrypt is rotating intermediate CA E5/E6. Clients pinning the old "
            "intermediate chain will experience TLS failures. A 48-hour misissuance window "
            "was also discovered in the new pipeline."
        ),
        "why_now": "Rotation begins 2026-03-10; 48-hour remediation window before breakage.",
        "confidence": 0.88,
        "recommended_actions_24h": [
            "Remove any hard-pinned Let's Encrypt intermediate certificate from trust stores.",
            "Test certificate chain validation against the new E5/E6 intermediates.",
        ],
        "recommended_actions_7d": [
            "Implement OCSP stapling on all public-facing TLS endpoints.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://letsencrypt.org/2026/03/intermediate-rotation",
                    "title": "Let's Encrypt Blog",
                },
            ]
        },
    },
    {
        "title": "Maven Central — compromised contributor account, 14 artifacts affected",
        "risk_score": 66,
        "priority": "P2",
        "domains": ["pkg_maven", "supply_chain"],
        "summary": (
            "A compromised Sonatype contributor account published backdoored versions of "
            "14 popular Spring Boot starter POMs. Backdoor phones home on context refresh."
        ),
        "why_now": "Artifacts remain in Central mirror cache; many builds not yet re-resolved.",
        "confidence": 0.83,
        "recommended_actions_24h": [
            "Clear local .m2 cache and force dependency re-resolution.",
            "Check SBOM against published IOC hash list.",
        ],
        "recommended_actions_7d": [
            "Enforce Sigstore artifact signing verification in Maven build pipeline.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://sonatype.com/blog/maven-central-compromise-2026",
                    "title": "Sonatype Blog",
                },
                {
                    "url": "https://www.securityweek.com/maven-central-supply-chain/",
                    "title": "SecurityWeek",
                },
            ]
        },
    },
    # ── P2 / Medium ──────────────────────────────────────────────────────────
    {
        "title": "Chrome extension 'TabManager Pro' data harvesting 2.1M users",
        "risk_score": 63,
        "priority": "P2",
        "domains": ["browser_ext", "identity"],
        "summary": (
            "Chrome Web Store extension with 2.1M installs silently exfiltrates browsed URLs, "
            "form autofill values, and session cookies to a third-party analytics endpoint "
            "with no user disclosure."
        ),
        "why_now": "Google has been notified but extension remains live. Cookie theft vector is active.",
        "confidence": 0.87,
        "recommended_actions_24h": [
            "Remove TabManager Pro from all managed Chrome instances via policy.",
            "Alert users to revoke any recently created sessions that may be affected.",
        ],
        "recommended_actions_7d": [
            "Audit Chrome extension allowlist via enterprise policy.",
            "Enforce extension install source restrictions.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://www.bleepingcomputer.com/news/security/tabmanager-pro-spyware/",
                    "title": "BleepingComputer",
                },
                {
                    "url": "https://krebsonsecurity.com/2026/03/tab-manager-pro/",
                    "title": "Krebs on Security",
                },
            ]
        },
    },
    {
        "title": "NuGet — 'Microsoft.Extensions.Logging.Abstractions' typosquat detected",
        "risk_score": 61,
        "priority": "P2",
        "domains": ["pkg_nuget", "supply_chain"],
        "summary": (
            "A typosquatting package 'Microsoft.Extensions.Logging.Abstracion' (one 's' dropped) "
            "has accumulated 8,200 downloads. Package executes embedded shellcode on .NET 8 runtime."
        ),
        "why_now": "Package ID is syntactically plausible in auto-complete; developer confusion likely.",
        "confidence": 0.90,
        "recommended_actions_24h": [
            "Search CI build logs for the misspelled package name.",
            "Add package to internal blocked-packages.json.",
        ],
        "recommended_actions_7d": [
            "Enforce NuGet package source whitelisting in nuget.config.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://devblogs.microsoft.com/nuget/security-advisory-march-2026",
                    "title": "NuGet Security Advisory",
                },
            ]
        },
    },
    # ── P3 / Medium ──────────────────────────────────────────────────────────
    {
        "title": "RubyGems 'devise-jwt' auth bypass in older token validation path",
        "risk_score": 54,
        "priority": "P3",
        "domains": ["pkg_gem", "identity", "web_framework"],
        "summary": (
            "A token-validation bypass in devise-jwt < 0.11.0 allows session reuse after "
            "logout when the denylist strategy is used. CVSS 7.1."
        ),
        "why_now": "Gem version 0.10.x still widely used; many Rails 7 apps vulnerable.",
        "confidence": 0.77,
        "recommended_actions_24h": [
            "Upgrade devise-jwt to 0.11.0+.",
        ],
        "recommended_actions_7d": [
            "Review JTI claim handling in all JWT-protected Rails endpoints.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://github.com/waiting-for-dev/devise-jwt/security/advisories/GHSA-xxxx",
                    "title": "GitHub Advisory",
                },
            ]
        },
    },
    {
        "title": "Kubernetes kube-proxy nodePort leak — internal services reachable externally",
        "risk_score": 58,
        "priority": "P2",
        "domains": ["container", "os_kernel"],
        "summary": (
            "A misconfiguration in kube-proxy iptables rules on multi-homed nodes causes "
            "ClusterIP services to be reachable on nodePort ranges from external networks."
        ),
        "why_now": "Issue reproducible on EKS 1.28 default node group configurations.",
        "confidence": 0.71,
        "recommended_actions_24h": [
            "Apply network policy denying external access to ClusterIP service CIDRs.",
        ],
        "recommended_actions_7d": [
            "Review kube-proxy mode (iptables vs ipvs) and externalTrafficPolicy settings.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://github.com/kubernetes/kubernetes/issues/120899",
                    "title": "Kubernetes GitHub Issue",
                },
            ]
        },
    },
    {
        "title": "Cloudflare Turnstile bypass technique published — bot-mitigation gap",
        "risk_score": 45,
        "priority": "P3",
        "domains": ["web_framework", "browser_ext"],
        "summary": (
            "A researcher published a technique combining headless browser fingerprint spoofing "
            "and timing manipulation to pass Cloudflare Turnstile challenges at scale."
        ),
        "why_now": "Automated attack tooling released 48h after initial disclosure.",
        "confidence": 0.65,
        "recommended_actions_24h": [],
        "recommended_actions_7d": [
            "Add secondary server-side rate-limiting behind Turnstile-protected endpoints.",
            "Consider honeypot fields for high-value form submissions.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://blog.cloudflare.com/turnstile-research-march-2026",
                    "title": "Cloudflare Blog",
                },
            ]
        },
    },
    {
        "title": "Node.js 20 LTS — path traversal in built-in serve() (low severity)",
        "risk_score": 38,
        "priority": "P3",
        "domains": ["pkg_npm", "web_framework"],
        "summary": (
            "The experimental node:http built-in serve() method fails to normalise paths "
            "with encoded sequences, allowing directory traversal on Windows hosts."
        ),
        "why_now": "Only affects developers using experimental API; production impact low.",
        "confidence": 0.68,
        "recommended_actions_24h": [],
        "recommended_actions_7d": [
            "Avoid using experimental node:http serve() in production until 20.12.1 patch.",
        ],
        "sources": {
            "primary": [
                {
                    "url": "https://nodejs.org/en/blog/vulnerability/march-2026-security-releases",
                    "title": "Node.js Security Releases",
                },
            ]
        },
    },
]


# ---------------------------------------------------------------------------
# Heatmap — mirrors what _findings_to_cards() builds from cards
# ---------------------------------------------------------------------------
def _build_heatmap(cards):
    from agent.runner import _TAXONOMY

    hm = {}
    for key, meta in _TAXONOMY.items():
        sub = [c for c in cards if key in c.get("domains", [])]
        hm[key] = {
            "label": meta["label"],
            "count": len(sub),
            "max_score": max((c["risk_score"] for c in sub), default=0),
        }
    # uncategorised
    uncat = [
        c for c in cards if not c.get("domains") or c["domains"] == ["uncategorised"]
    ]
    hm["uncategorised"] = {"label": "Other", "count": len(uncat), "max_score": 0}
    return hm


# ---------------------------------------------------------------------------
# Mock history — drives the sparkline trend panel
# ---------------------------------------------------------------------------
MOCK_HISTORY = [
    {"counts": {"polled": 42, "clusters": 4}},
    {"counts": {"polled": 67, "clusters": 7}},
    {"counts": {"polled": 51, "clusters": 6}},
    {"counts": {"polled": 88, "clusters": 11}},
    {"counts": {"polled": 73, "clusters": 9}},
    {"counts": {"polled": 95, "clusters": 14}},
    {"counts": {"polled": 110, "clusters": 16}},
]

# ---------------------------------------------------------------------------
# Mock executive summary
# ---------------------------------------------------------------------------
MOCK_EXECUTIVE = (
    "This cycle surfaces critical supply-chain and identity threats requiring immediate action. "
    "An actively exploited OpenSSL 3.x RCE (CVE-2026-1001) is the highest-priority item — "
    "patch all hosts before end of business today. Two npm and PyPI packages with credential-theft "
    "payloads are live in CI pipelines. An Okta SAML zero-day with confirmed tenant breaches "
    "demands hotfix deployment and privileged session revocation. Secondary focus: AWS Lambda "
    "confused-deputy chains and a Let's Encrypt intermediate CA rotation that starts in 5 days."
)

# ---------------------------------------------------------------------------
# Generate
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    heatmap = _build_heatmap(MOCK_CARDS)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    _write_index_html(
        path="reports/index.html",
        cards=MOCK_CARDS,
        heatmap=heatmap,
        ts=ts,
        executive=MOCK_EXECUTIVE,
        history=MOCK_HISTORY,
    )

    print(f"[OK] reports/index.html written -- {len(MOCK_CARDS)} mock findings")
    print("     Open reports/index.html in a browser to review all components.")
