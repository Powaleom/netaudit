# netaudit report: `sample_configs/router_insecure.cfg`

**Hardening score:** 0/100 (rough heuristic)  
**Findings:** 6 high, 9 medium, 4 low, 0 info

## [HIGH] NA-001: Telnet allowed on VTY lines

- **Why it matters:** Telnet sends credentials and commands in clear text, so anyone who can sniff the path can read them.
- **Fix:** Set `transport input ssh` on every `line vty` block and enforce SSH version 2.
- **Reference:** MITRE ATT&CK T1040 (Network Sniffing)

```
line 40: transport input all
```

## [HIGH] NA-005: `enable password` in use

- **Why it matters:** It is stored in clear text or with the reversible type 7 encoding.
- **Fix:** Remove it and use `enable secret` with a strong hash (type 8 or 9 where supported).

```
line 9: enable password <redacted>
```

## [HIGH] NA-006: No `enable secret` configured

- **Why it matters:** Privileged EXEC mode is not protected by a hashed secret.
- **Fix:** Configure `enable secret` (type 8 or 9 where supported), or rely on AAA with local users.

## [HIGH] NA-007: Clear-text passwords on lines or users

- **Why it matters:** Anyone who can read the config (backups, tickets, screenshots) can read these passwords.
- **Fix:** Use `username <name> secret <hash-type> ...` and `login local` instead of line passwords.
- **Reference:** MITRE ATT&CK T1552 (Unsecured Credentials)

```
line 11: username admin privilege 15 password 0 <redacted>
line 35: password <redacted>
line 38: password <redacted>
```

## [HIGH] NA-012: Well-known SNMP community strings

- **Why it matters:** Default strings such as public/private are the first thing scanners try.
- **Fix:** Remove them. Prefer SNMPv3 with authentication and encryption (`snmp-server group ... v3 priv`).
- **Reference:** MITRE ATT&CK T1602.001 (SNMP MIB Dump)

```
line 29: snmp-server community public RO
line 30: snmp-server community private RW
```

## [HIGH] NA-013: SNMP read-write community configured

- **Why it matters:** Anyone holding the string can change device configuration over SNMPv1/v2c.
- **Fix:** Remove RW communities; use SNMPv3 if write access is truly required.

```
line 30: snmp-server community private RW
```

## [MEDIUM] NA-003: No access-class restricting management access

- **Why it matters:** Any reachable host can attempt to log in to the VTY lines.
- **Fix:** Create a standard ACL of trusted management subnets and apply it with `access-class <ACL> in`.

```
line 37: line vty 0 4
```

## [MEDIUM] NA-004: Sessions never time out (exec-timeout 0 0)

- **Why it matters:** An abandoned privileged session stays open indefinitely.
- **Fix:** Use a finite timeout such as `exec-timeout 10 0` on console and VTY lines.

```
line 34: exec-timeout 0 0
```

## [MEDIUM] NA-008: Reversible type 7 passwords

- **Why it matters:** Type 7 is obfuscation, not encryption; freely available tools reverse it instantly.
- **Fix:** Replace with `secret` entries using type 8 or 9 (or type 5 if nothing stronger is available).
- **Reference:** MITRE ATT&CK T1552 (Unsecured Credentials)

```
line 12: username ops password 7 <redacted>
```

## [MEDIUM] NA-014: SNMP community not restricted by ACL

- **Why it matters:** Any host that learns the string can query the device.
- **Fix:** Append a standard ACL of your monitoring servers to each community, or move to SNMPv3.

```
line 29: snmp-server community public RO
line 30: snmp-server community private RW
line 31: snmp-server community <redacted> RO
```

## [MEDIUM] NA-015: Plain HTTP management server enabled

- **Why it matters:** The web UI sends credentials unencrypted and enlarges the attack surface.
- **Fix:** Use `no ip http server`; if a web UI is needed, use `ip http secure-server` with an ACL.

```
line 15: ip http server
```

## [MEDIUM] NA-016: ACL permits any source to any destination

- **Why it matters:** An `any any` permit defeats the purpose of the ACL unless it is deliberately last and reviewed.
- **Fix:** Narrow the rule to required sources, destinations and ports, and end with an explicit `deny ip any any log`.

```
line 27: [ip access-list extended OUTSIDE-IN] permit ip any any
```

## [MEDIUM] NA-017: No remote syslog server configured

- **Why it matters:** Logs kept only on the device are lost on reload and can be erased by an intruder.
- **Fix:** Add `logging host <ip>` pointing at a central log collector or SIEM.

## [MEDIUM] NA-020: AAA is not enabled

- **Why it matters:** Without AAA there is no centralised authentication, authorization or accounting.
- **Fix:** Enable `aaa new-model` and configure TACACS+/RADIUS with a local fallback.

## [MEDIUM] NA-021: SSH version 2 not enforced

- **Why it matters:** SSHv1 has known cryptographic weaknesses.
- **Fix:** Set `ip ssh version 2` (requires a hostname, domain name and RSA keys of at least 2048 bits).

## [LOW] NA-011: `service password-encryption` is not enabled

- **Why it matters:** Any remaining line-level passwords are stored in plain text.
- **Fix:** Enable it as a safety net, but migrate to `secret` rather than relying on it.

## [LOW] NA-018: Log timestamps not enabled

- **Why it matters:** Log entries without timestamps are hard to correlate during an investigation.
- **Fix:** Use `service timestamps log datetime msec`.

## [LOW] NA-019: No NTP source configured

- **Why it matters:** Unsynchronised clocks make logs unreliable across devices.
- **Fix:** Configure at least two `ntp server` entries.

## [LOW] NA-022: No login banner

- **Why it matters:** A legal warning banner supports policy enforcement and shows access is restricted.
- **Fix:** Add `banner login` with an authorized-use-only notice approved by your organization.

