"""Security helpers for browser-harness.

Provides:
- telemetry disabled by default (see telemetry.py changes)
- prompt-injection detection for both input (code sent to the harness) and
  output (text the harness prints, e.g. page content).
"""

from __future__ import annotations

import os
import re
import sys

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_previous", re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", re.I)),
    ("disregard", re.compile(r"disregard\s+(the\s+)?(above|previous|system|prior)", re.I)),
    ("new_instructions", re.compile(r"new\s+instructions\s*:", re.I)),
    ("system_prompt", re.compile(r"system\s*prompt", re.I)),
    ("role_override", re.compile(r"you\s+are\s+now\b", re.I)),
    ("act_as", re.compile(r"\bact\s+as\b", re.I)),
    ("jailbreak", re.compile(r"jailbreak", re.I)),
    ("dan_mode", re.compile(r"\bDAN\b|\bdo\s+anything\s+now\b", re.I)),
    ("forget", re.compile(r"forget\s+(everything|all|your\s+(instructions|rules|role))", re.I)),
    ("override", re.compile(r"\boverride\s+(the\s+)?(system|instructions|rules|safety)", re.I)),
    ("chatml", re.compile(r"<\|im_start\|>|<\|im_end\|>|\[INST\]|<<SYS>>|<\|system\|>", re.I)),
    ("exfil", re.compile(r"(exfiltrate|send\s+.{0,40}to\s+https?://|curl\s+.{0,40}https?://)", re.I)),
    ("base64_blob", re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")),
]

_HIGH_SIGNAL = {"ignore_previous", "disregard", "new_instructions", "system_prompt",
                "role_override", "jailbreak", "dan_mode", "forget", "override",
                "chatml", "exfil"}


def detect(text: str) -> tuple[bool, list[str]]:
    if not text:
        return False, []
    findings: list[str] = []
    for name, pat in _INJECTION_PATTERNS:
        if pat.search(text):
            findings.append(name)
    suspicious = any(f in _HIGH_SIGNAL for f in findings) or len(findings) >= 2
    return suspicious, findings


def scan_input(code: str) -> tuple[bool, list[str]]:
    return detect(code)


def scan_output(text: str) -> tuple[bool, list[str]]:
    return detect(text)


def security_mode() -> str:
    return (os.environ.get("BH_SECURITY_MODE") or "block").lower()


def override_allowed() -> bool:
    return (os.environ.get("BH_SECURITY_OVERRIDE") or "").lower() in {"1", "true", "yes"}


def guard_input(code: str) -> bool:
    suspicious, findings = scan_input(code)
    if not suspicious:
        return True
    msg = "browser-harness SECURITY: potential prompt injection detected in input (" + ", ".join(findings) + ")."
    print(msg, file=sys.stderr)
    if security_mode() == "warn" or override_allowed():
        print("browser-harness SECURITY: proceeding due to mode/override.", file=sys.stderr)
        return True
    print("browser-harness SECURITY: execution blocked. Set BH_SECURITY_MODE=warn or BH_SECURITY_OVERRIDE=1 to override.", file=sys.stderr)
    return False


class Tee:
    def __init__(self, original):
        self.original = original
        self.buffer = []

    def write(self, data):
        try:
            self.original.write(data)
        except Exception:
            pass
        self.buffer.append(data)
        try:
            return len(data)
        except Exception:
            return 0

    def flush(self):
        try:
            self.original.flush()
        except Exception:
            pass

    def getvalue(self) -> str:
        return "".join(self.buffer)