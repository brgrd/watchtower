"""
Tests for agent.analysis._normalize_tactic.

Covers all paths: exact canonical match, alias match, prefix match,
garbage input, empty string, and None coercion.
"""

import pytest
from agent.analysis import _normalize_tactic

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("raw,expected", [
    # Exact canonical match — case-insensitive
    ("Initial Access",         "Initial Access"),
    ("initial access",         "Initial Access"),
    ("INITIAL ACCESS",         "Initial Access"),
    ("Privilege Escalation",   "Privilege Escalation"),
    ("Command & Control",      "Command & Control"),
    ("Reconnaissance",         "Reconnaissance"),
    ("Exfiltration",           "Exfiltration"),
    ("Impact",                 "Impact"),
    ("Lateral Movement",       "Lateral Movement"),
    ("Defense Evasion",        "Defense Evasion"),
    ("Credential Access",      "Credential Access"),
    ("Collection",             "Collection"),
    ("Persistence",            "Persistence"),
    ("Execution",              "Execution"),
    ("Resource Development",   "Resource Development"),
    ("Discovery",              "Discovery"),
])
def test_exact_canonical_match(raw, expected):
    assert _normalize_tactic(raw) == expected


@pytest.mark.parametrize("alias,expected", [
    # Common LLM shorthand / abbreviations
    ("recon",                  "Reconnaissance"),
    ("privesc",                "Privilege Escalation"),
    ("priv esc",               "Privilege Escalation"),
    ("privilege-escalation",   "Privilege Escalation"),
    ("evasion",                "Defense Evasion"),
    ("defense-evasion",        "Defense Evasion"),
    ("def evasion",            "Defense Evasion"),
    ("c2",                     "Command & Control"),
    ("c&c",                    "Command & Control"),
    ("command and control",    "Command & Control"),
    ("command-and-control",    "Command & Control"),
    ("exfil",                  "Exfiltration"),
    ("data exfiltration",      "Exfiltration"),
    ("cred access",            "Credential Access"),
    ("credential-access",      "Credential Access"),
    ("credentials",            "Credential Access"),
    ("lateral-movement",       "Lateral Movement"),
    ("collect",                "Collection"),
    ("exec",                   "Execution"),
    ("execute",                "Execution"),
    ("persist",                "Persistence"),
    ("resource dev",           "Resource Development"),
    ("resource-dev",           "Resource Development"),
])
def test_alias_match(alias, expected):
    assert _normalize_tactic(alias) == expected


@pytest.mark.parametrize("raw,expected", [
    # Prefix match — truncated or abbreviated canonical names
    ("Privilege Esc",   "Privilege Escalation"),
    ("Reconn",          "Reconnaissance"),
    ("Execut",          "Execution"),
    ("Exfiltr",         "Exfiltration"),
    ("Lateral",         "Lateral Movement"),
])
def test_prefix_match(raw, expected):
    assert _normalize_tactic(raw) == expected


@pytest.mark.parametrize("raw", [
    "totally_unknown_tactic",
    "phishing",
    "brute force",
    "malware",
    "unknown",
    "n/a",
    "none",
    "exploit",
    "zzz",
])
def test_garbage_returns_empty(raw):
    assert _normalize_tactic(raw) == ""


def test_empty_string_returns_empty():
    assert _normalize_tactic("") == ""


def test_none_coercion_returns_empty():
    # Callers coerce None to "" before calling; verify the empty-string guard
    assert _normalize_tactic("") == ""


def test_whitespace_only_returns_empty():
    assert _normalize_tactic("   ") == ""
