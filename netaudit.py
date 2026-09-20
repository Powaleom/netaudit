#!/usr/bin/env python3
"""netaudit: a small hardening auditor for Cisco IOS / IOS-XE configuration files.

Reads a saved `show running-config` (plain text) and reports common security
misconfigurations, each with a severity, evidence (secrets redacted) and a
suggested fix. Standard library only. Read-only: it never connects to a device.

Only audit configurations you own or are authorized to review.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

__version__ = "0.1.0"

SEVERITIES = ["HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"HIGH": 15, "MEDIUM": 7, "LOW": 2, "INFO": 0}
WEAK_COMMUNITIES = {"public", "private", "cisco", "community", "snmp"}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Finding:
    id: str
    severity: str
    title: str
    why: str
    fix: str
    evidence: list = field(default_factory=list)  # [(line_no, text)]
    ref: str = ""


@dataclass
class Block:
    header: str
    line_no: int
    children: list = field(default_factory=list)  # [(line_no, text)]


@dataclass
class Config:
    top: list = field(default_factory=list)     # [(line_no, text)] top-level lines
    blocks: list = field(default_factory=list)  # [Block], one per top-level line

    def top_matching(self, pattern: str):
        rx = re.compile(pattern, re.I)
        return [(n, t) for n, t in self.top if rx.search(t)]

    def blocks_starting(self, prefix: str):
        p = prefix.lower()
        return [b for b in self.blocks if b.header.lower().startswith(p)]

    def all_lines(self):
        for n, t in self.top:
            yield n, t
        for b in self.blocks:
            for n, t in b.children:
                yield n, t


# --------------------------------------------------------------------------
# Parsing and redaction
# --------------------------------------------------------------------------
def parse(text: str) -> Config:
    """Split a Cisco-style config into top-level lines and their indented children."""
    cfg = Config()
    current = None
    banner_end = None
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if banner_end is not None:          # inside a multi-line banner
            if banner_end in line:
                banner_end = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            current = None
            continue
        if line[0] in " \t":
            if current is not None:
                current.children.append((no, stripped))
            continue
        current = Block(stripped, no)
        cfg.blocks.append(current)
        cfg.top.append((no, stripped))
        m = re.match(r"banner\s+\w+\s+(.*)$", stripped, re.I)
        if m:
            rest = m.group(1)
            delim = "^C" if rest.startswith("^C") else rest[:1]
            if delim and rest.count(delim) < 2:
                banner_end = delim
            current = None
    return cfg


_SECRET_RE = re.compile(r"(\b(?:password|secret)\s+(?:\d\s+)?)(\S+)", re.I)


def redact(text: str) -> str:
    """Mask passwords, hashes and non-default SNMP communities in evidence lines."""
    m = re.match(r"^(snmp-server\s+community\s+)(\S+)(.*)$", text, re.I)
    if m:
        if m.group(2).lower() in WEAK_COMMUNITIES:
            return text  # a well-known community string is itself the finding
        return f"{m.group(1)}<redacted>{m.group(3)}"
    return _SECRET_RE.sub(lambda mm: mm.group(1) + "<redacted>", text)


def finding(id_, sev, title, why, fix, evidence=None, ref=""):
    ev = [(n, redact(t)) for n, t in (evidence or [])]
    return Finding(id_, sev, title, why, fix, ev, ref)


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def vty_transport(cfg):
    out, risky, unspecified = [], [], []
    for b in cfg.blocks_starting("line vty"):
        transports = [(n, t) for n, t in b.children if t.lower().startswith("transport input")]
        if not transports:
            unspecified.append((b.line_no, b.header))
            continue
        for n, t in transports:
            words = t.lower().split()[2:]
            if "telnet" in words or "all" in words:
                risky.append((n, t))
    if risky:
        out.append(finding(
            "NA-001", "HIGH", "Telnet allowed on VTY lines",
            "Telnet sends credentials and commands in clear text, so anyone who can sniff the path can read them.",
            "Set `transport input ssh` on every `line vty` block and enforce SSH version 2.",
            risky, "MITRE ATT&CK T1040 (Network Sniffing)"))
    if unspecified:
        out.append(finding(
            "NA-002", "MEDIUM", "VTY transport not restricted",
            "Without `transport input`, older IOS releases accept Telnet by default.",
            "Add `transport input ssh` under each `line vty` block.",
            unspecified))
    return out


@check
def vty_access_class(cfg):
    missing = [(b.line_no, b.header) for b in cfg.blocks_starting("line vty")
               if not any(t.lower().startswith("access-class") for _, t in b.children)]
    if not missing:
        return []
    return [finding(
        "NA-003", "MEDIUM", "No access-class restricting management access",
        "Any reachable host can attempt to log in to the VTY lines.",
        "Create a standard ACL of trusted management subnets and apply it with `access-class <ACL> in`.",
        missing)]


@check
def exec_timeout(cfg):
    hits = [(n, t) for b in cfg.blocks_starting("line ") for n, t in b.children
            if re.match(r"exec-timeout\s+0\s+0\b", t, re.I)]
    if not hits:
        return []
    return [finding(
        "NA-004", "MEDIUM", "Sessions never time out (exec-timeout 0 0)",
        "An abandoned privileged session stays open indefinitely.",
        "Use a finite timeout such as `exec-timeout 10 0` on console and VTY lines.", hits)]


@check
def enable_password(cfg):
    out = []
    pw = cfg.top_matching(r"^enable\s+password\b")
    if pw:
        out.append(finding(
            "NA-005", "HIGH", "`enable password` in use",
            "It is stored in clear text or with the reversible type 7 encoding.",
            "Remove it and use `enable secret` with a strong hash (type 8 or 9 where supported).", pw))
    if not cfg.top_matching(r"^enable\s+secret\b"):
        out.append(finding(
            "NA-006", "HIGH", "No `enable secret` configured",
            "Privileged EXEC mode is not protected by a hashed secret.",
            "Configure `enable secret` (type 8 or 9 where supported), or rely on AAA with local users."))
    return out


_PW_RE = re.compile(r"^(?:username\s+\S+\s+(?:privilege\s+\d+\s+)?)?password\s+(?:(\d)\s+)?(\S+)", re.I)


@check
def plain_and_type7_passwords(cfg):
    plain, type7 = [], []
    for n, t in cfg.all_lines():
        if t.lower().startswith("enable"):
            continue  # handled by NA-005
        m = _PW_RE.match(t)
        if not m:
            continue
        if m.group(1) == "7":
            type7.append((n, t))
        elif m.group(1) in (None, "0"):
            plain.append((n, t))
    out = []
    if plain:
        out.append(finding(
            "NA-007", "HIGH", "Clear-text passwords on lines or users",
            "Anyone who can read the config (backups, tickets, screenshots) can read these passwords.",
            "Use `username <name> secret <hash-type> ...` and `login local` instead of line passwords.",
            plain, "MITRE ATT&CK T1552 (Unsecured Credentials)"))
    if type7:
        out.append(finding(
            "NA-008", "MEDIUM", "Reversible type 7 passwords",
            "Type 7 is obfuscation, not encryption; freely available tools reverse it instantly.",
            "Replace with `secret` entries using type 8 or 9 (or type 5 if nothing stronger is available).",
            type7, "MITRE ATT&CK T1552 (Unsecured Credentials)"))
    return out


@check
def weak_secret_types(cfg):
    t4, t5 = [], []
    for n, t in cfg.all_lines():
        m = re.search(r"\bsecret\s+(\d)\s+\S+", t, re.I)
        if m and m.group(1) == "4":
            t4.append((n, t))
        elif m and m.group(1) == "5":
            t5.append((n, t))
    out = []
    if t4:
        out.append(finding(
            "NA-009", "MEDIUM", "Type 4 secrets in use",
            "Type 4 has a known implementation weakness and is considered insecure.",
            "Re-enter these secrets as type 8 or 9.", t4))
    if t5:
        out.append(finding(
            "NA-010", "LOW", "Type 5 (MD5-based) secrets in use",
            "Type 5 is salted but based on MD5, which is weak against modern cracking hardware.",
            "Move to type 8 or 9 where the platform supports it.", t5))
    return out


@check
def password_encryption(cfg):
    if cfg.top_matching(r"^service\s+password-encryption\b"):
        return []
    return [finding(
        "NA-011", "LOW", "`service password-encryption` is not enabled",
        "Any remaining line-level passwords are stored in plain text.",
        "Enable it as a safety net, but migrate to `secret` rather than relying on it.")]


def _snmp_communities(cfg):
    for n, t in cfg.top:
        toks = t.split()
        if len(toks) >= 3 and toks[0].lower() == "snmp-server" and toks[1].lower() == "community":
            rest, mode, leftover, i = toks[3:], None, [], 0
            while i < len(rest):
                w = rest[i].lower()
                if w == "view" and i + 1 < len(rest):
                    i += 2
                    continue
                if w in ("ro", "rw"):
                    mode = w.upper()
                else:
                    leftover.append(rest[i])
                i += 1
            yield n, t, toks[2], mode, bool(leftover)


@check
def snmp(cfg):
    weak, rw, no_acl = [], [], []
    for n, t, community, mode, has_acl in _snmp_communities(cfg):
        if community.lower() in WEAK_COMMUNITIES:
            weak.append((n, t))
        if mode == "RW":
            rw.append((n, t))
        if not has_acl:
            no_acl.append((n, t))
    out = []
    if weak:
        out.append(finding(
            "NA-012", "HIGH", "Well-known SNMP community strings",
            "Default strings such as public/private are the first thing scanners try.",
            "Remove them. Prefer SNMPv3 with authentication and encryption (`snmp-server group ... v3 priv`).",
            weak, "MITRE ATT&CK T1602.001 (SNMP MIB Dump)"))
    if rw:
        out.append(finding(
            "NA-013", "HIGH", "SNMP read-write community configured",
            "Anyone holding the string can change device configuration over SNMPv1/v2c.",
            "Remove RW communities; use SNMPv3 if write access is truly required.", rw))
    if no_acl:
        out.append(finding(
            "NA-014", "MEDIUM", "SNMP community not restricted by ACL",
            "Any host that learns the string can query the device.",
            "Append a standard ACL of your monitoring servers to each community, or move to SNMPv3.", no_acl))
    return out


@check
def http_server(cfg):
    hits = [(n, t) for n, t in cfg.top if t.lower() == "ip http server"]
    if not hits:
        return []
    return [finding(
        "NA-015", "MEDIUM", "Plain HTTP management server enabled",
        "The web UI sends credentials unencrypted and enlarges the attack surface.",
        "Use `no ip http server`; if a web UI is needed, use `ip http secure-server` with an ACL.", hits)]


_ANY_ANY = re.compile(r"\bpermit\s+(ip|tcp|udp)\s+any\s+any\s*(log(-input)?)?\s*$", re.I)


@check
def permit_any_any(cfg):
    hits = []
    for b in cfg.blocks_starting("ip access-list"):
        hits += [(n, f"[{b.header}] {t}") for n, t in b.children if _ANY_ANY.search(t)]
    hits += [(n, t) for n, t in cfg.top_matching(r"^access-list\s+\d+\s+") if _ANY_ANY.search(t)]
    if not hits:
        return []
    return [finding(
        "NA-016", "MEDIUM", "ACL permits any source to any destination",
        "An `any any` permit defeats the purpose of the ACL unless it is deliberately last and reviewed.",
        "Narrow the rule to required sources, destinations and ports, and end with an explicit `deny ip any any log`.",
        hits)]


@check
def remote_logging(cfg):
    if cfg.top_matching(r"^logging\s+(host|server)\s+\S+") or cfg.top_matching(r"^logging\s+\d+\.\d+\.\d+\.\d+"):
        return []
    return [finding(
        "NA-017", "MEDIUM", "No remote syslog server configured",
        "Logs kept only on the device are lost on reload and can be erased by an intruder.",
        "Add `logging host <ip>` pointing at a central log collector or SIEM.")]


@check
def log_timestamps(cfg):
    if cfg.top_matching(r"^service\s+timestamps\s+log\b"):
        return []
    return [finding(
        "NA-018", "LOW", "Log timestamps not enabled",
        "Log entries without timestamps are hard to correlate during an investigation.",
        "Use `service timestamps log datetime msec`.")]


@check
def ntp(cfg):
    if cfg.top_matching(r"^ntp\s+(server|peer)\b"):
        return []
    return [finding(
        "NA-019", "LOW", "No NTP source configured",
        "Unsynchronised clocks make logs unreliable across devices.",
        "Configure at least two `ntp server` entries.")]


@check
def aaa(cfg):
    if cfg.top_matching(r"^aaa\s+new-model\b"):
        return []
    return [finding(
        "NA-020", "MEDIUM", "AAA is not enabled",
        "Without AAA there is no centralised authentication, authorization or accounting.",
        "Enable `aaa new-model` and configure TACACS+/RADIUS with a local fallback.")]


@check
def ssh_version(cfg):
    if cfg.top_matching(r"^ip\s+ssh\s+version\s+2\b"):
        return []
    return [finding(
        "NA-021", "MEDIUM", "SSH version 2 not enforced",
        "SSHv1 has known cryptographic weaknesses.",
        "Set `ip ssh version 2` (requires a hostname, domain name and RSA keys of at least 2048 bits).")]


@check
def banner(cfg):
    if cfg.top_matching(r"^banner\s+(login|motd|exec)\b"):
        return []
    return [finding(
        "NA-022", "LOW", "No login banner",
        "A legal warning banner supports policy enforcement and shows access is restricted.",
        "Add `banner login` with an authorized-use-only notice approved by your organization.")]


# --------------------------------------------------------------------------
# Running audits and reporting
# --------------------------------------------------------------------------
def audit_text(text: str):
    cfg = parse(text)
    findings = []
    for fn in CHECKS:
        findings.extend(fn(cfg))
    return sorted(findings, key=lambda f: (SEV_RANK[f.severity], f.id))


def score(findings) -> int:
    return max(0, 100 - sum(SEV_WEIGHT[f.severity] for f in findings))


def counts(findings) -> dict:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


def render_text(name, findings) -> str:
    c = counts(findings)
    lines = [f"netaudit {__version__}  |  {name}",
             f"Hardening score: {score(findings)}/100 (rough heuristic)   "
             f"High: {c['HIGH']}  Medium: {c['MEDIUM']}  Low: {c['LOW']}  Info: {c['INFO']}",
             "-" * 72]
    if not findings:
        lines.append("No findings.")
    for f in findings:
        lines += [f"[{f.severity}] {f.id}  {f.title}", f"  Why: {f.why}", f"  Fix: {f.fix}"]
        if f.ref:
            lines.append(f"  Ref: {f.ref}")
        if f.evidence:
            lines.append("  Evidence:")
            lines += [f"    line {n}: {t}" for n, t in f.evidence]
        lines.append("")
    return "\n".join(lines)


def render_markdown(name, findings) -> str:
    c = counts(findings)
    out = [f"# netaudit report: `{name}`", "",
           f"**Hardening score:** {score(findings)}/100 (rough heuristic)  ",
           f"**Findings:** {c['HIGH']} high, {c['MEDIUM']} medium, {c['LOW']} low, {c['INFO']} info", ""]
    if not findings:
        out.append("No findings.")
    for f in findings:
        out += [f"## [{f.severity}] {f.id}: {f.title}", "",
                f"- **Why it matters:** {f.why}", f"- **Fix:** {f.fix}"]
        if f.ref:
            out.append(f"- **Reference:** {f.ref}")
        if f.evidence:
            out += ["", "```"] + [f"line {n}: {t}" for n, t in f.evidence] + ["```"]
        out.append("")
    return "\n".join(out)


def build_parser():
    p = argparse.ArgumentParser(
        prog="netaudit",
        description="Audit Cisco IOS/IOS-XE config files for common security misconfigurations (read-only).")
    p.add_argument("configs", nargs="+", help="path(s) to saved running-config text files")
    p.add_argument("-f", "--format", choices=["text", "markdown", "json"], default="text")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                   help="hide findings below this severity (default: INFO, show all)")
    p.add_argument("--fail-on", choices=[s.lower() for s in SEVERITIES] + ["none"], default="none",
                   help="exit with status 2 if any finding at or above this severity exists")
    p.add_argument("--version", action="version", version=f"netaudit {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    limit = SEV_RANK[args.min_severity]
    reports, worst = [], None
    for path in args.configs:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"netaudit: cannot read {path}: {exc}", file=sys.stderr)
            return 1
        findings = [f for f in audit_text(text) if SEV_RANK[f.severity] <= limit]
        reports.append((path, findings))
        for f in findings:
            r = SEV_RANK[f.severity]
            worst = r if worst is None else min(worst, r)

    if args.format == "json":
        payload = [{"file": n, "score": score(fs), "counts": counts(fs),
                    "findings": [asdict(f) for f in fs]} for n, fs in reports]
        body = json.dumps(payload, indent=2)
    else:
        render = render_markdown if args.format == "markdown" else render_text
        body = "\n\n".join(render(n, fs) for n, fs in reports)

    if args.output:
        Path(args.output).write_text(body + "\n", encoding="utf-8")
    else:
        try:
            print(body)
        except BrokenPipeError:  # e.g. piped into `head`
            pass

    if args.fail_on != "none" and worst is not None and worst <= SEV_RANK[args.fail_on.upper()]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
