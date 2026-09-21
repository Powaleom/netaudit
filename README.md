# netaudit

A small, dependency-free hardening auditor for **Cisco IOS / IOS-XE** configuration files.

Point it at a saved `show running-config` and it reports common security misconfigurations, each with a
severity, the offending lines (secrets redacted), a short explanation and a suggested fix. It is
**read-only**: it parses a text file and never connects to a device.

> Only audit configurations you own or are authorized to review. Do not commit real device configs to
> public repositories; they contain sensitive network details.

## Quick start

Requires Python 3.9+. No packages to install. Keep the two sample `.cfg` files in a `sample_configs/` folder
next to `netaudit.py` (the tests also work if they sit in the same folder).

```bash
python3 netaudit.py sample_configs/router_insecure.cfg
python3 netaudit.py sample_configs/router_insecure.cfg -f markdown -o report.md
python3 netaudit.py router1.cfg router2.cfg -f json
python3 netaudit.py router1.cfg --min-severity MEDIUM --fail-on high   # exit code 2 if any HIGH finding
```

Run the tests:

```bash
python3 -m unittest -v
```

## Example output

```
netaudit 0.1.0  |  sample_configs/router_insecure.cfg
Hardening score: 0/100 (rough heuristic)   High: 6  Medium: 9  Low: 4  Info: 0
------------------------------------------------------------------------
[HIGH] NA-001  Telnet allowed on VTY lines
  Why: Telnet sends credentials and commands in clear text, so anyone who can sniff the path can read them.
  Fix: Set `transport input ssh` on every `line vty` block and enforce SSH version 2.
  Ref: MITRE ATT&CK T1040 (Network Sniffing)
  Evidence:
    line 40: transport input all
```

See `sample_report.md` for a full Markdown report.

## What it checks

| ID | Severity | Check |
|----|----------|-------|
| NA-001 | High | Telnet (or `transport input all`) allowed on VTY lines |
| NA-002 | Medium | VTY transport not restricted |
| NA-003 | Medium | No `access-class` limiting management access |
| NA-004 | Medium | `exec-timeout 0 0` (sessions never expire) |
| NA-005 | High | `enable password` in use |
| NA-006 | High | No `enable secret` |
| NA-007 | High | Clear-text passwords on lines or users |
| NA-008 | Medium | Reversible type 7 passwords |
| NA-009 | Medium | Type 4 secrets |
| NA-010 | Low | Type 5 (MD5-based) secrets |
| NA-011 | Low | `service password-encryption` not enabled |
| NA-012 | High | Well-known SNMP communities (public, private, ...) |
| NA-013 | High | SNMP read-write community |
| NA-014 | Medium | SNMP community without an ACL |
| NA-015 | Medium | Plain HTTP management server enabled |
| NA-016 | Medium | ACL entry permits `ip/tcp/udp any any` |
| NA-017 | Medium | No remote syslog server |
| NA-018 | Low | Log timestamps not enabled |
| NA-019 | Low | No NTP source |
| NA-020 | Medium | AAA not enabled |
| NA-021 | Medium | SSH version 2 not enforced |
| NA-022 | Low | No login banner |

The hardening score is a rough heuristic (100 minus weighted findings), meant for comparing a config
before and after fixes, not as a formal rating.

## How it works

1. `parse()` splits the config into top-level lines and their indented children (interfaces, `line vty`,
   ACLs), and skips multi-line banner text so it is not mistaken for commands.
2. Each check is a small function registered with `@check` that inspects the parsed config and returns
   zero or more `Finding` objects.
3. `redact()` masks passwords, hashes and non-default SNMP community strings before they reach any report.

Adding a check is one function:

```python
@check
def cdp_on_wan(cfg):
    ...
    return [finding("NA-023", "LOW", "Title", "Why it matters", "How to fix", evidence)]
```

## Limitations

- Line-based heuristics, not a full IOS parser. It can miss issues or flag things that are intentional,
  so treat findings as review prompts.
- Targets IOS / IOS-XE syntax. NX-OS, ASA, Junos and others are not supported yet.
- It looks only at the config text; it cannot see runtime state, software versions or known CVEs.
- Tested against the fictional sample configs in `sample_configs/`, plus unit tests. Try it on lab configs
  (for example from GNS3, EVE-NG or Packet Tracer) before relying on it.

## Ideas for next steps

- Support NX-OS and Fortinet or Palo Alto configuration formats.
- Map checks to a published hardening benchmark and cite control IDs.
- Diff two configs to show what a change fixed or introduced.
- Add an HTML report and a GitHub Actions workflow that fails a pull request on new HIGH findings.

## License

MIT. See the `LICENSE` file.
