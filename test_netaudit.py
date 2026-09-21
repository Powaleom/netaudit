"""Unit tests for netaudit. Run with:  python3 -m unittest -v"""
import contextlib
import io
import unittest
from pathlib import Path

import netaudit

ROOT = Path(__file__).parent
# Works whether the sample configs are in ./sample_configs/ or in the same folder as this file.
SAMPLES = ROOT / "sample_configs" if (ROOT / "sample_configs").is_dir() else ROOT


def audit(name):
    return netaudit.audit_text((SAMPLES / name).read_text())


def ids(findings):
    return {f.id for f in findings}


class InsecureConfigTests(unittest.TestCase):
    def setUp(self):
        self.findings = audit("router_insecure.cfg")

    def test_expected_findings_present(self):
        expected = {
            "NA-001",  # telnet on vty
            "NA-003",  # no access-class
            "NA-004",  # exec-timeout 0 0
            "NA-005",  # enable password
            "NA-006",  # no enable secret
            "NA-007",  # clear-text passwords
            "NA-008",  # type 7 passwords
            "NA-011",  # no password-encryption
            "NA-012",  # public/private
            "NA-013",  # RW community
            "NA-014",  # community without ACL
            "NA-015",  # ip http server
            "NA-016",  # permit ip any any
            "NA-017",  # no remote logging
            "NA-018",  # no log timestamps
            "NA-019",  # no NTP
            "NA-020",  # no AAA
            "NA-021",  # no SSHv2
            "NA-022",  # no banner
        }
        self.assertTrue(expected <= ids(self.findings), expected - ids(self.findings))

    def test_specific_port_rule_is_not_flagged_as_any_any(self):
        f = next(x for x in self.findings if x.id == "NA-016")
        joined = " ".join(t for _, t in f.evidence)
        self.assertIn("permit ip any any", joined)
        self.assertNotIn("eq 22", joined)

    def test_secrets_are_redacted_in_evidence(self):
        text = " ".join(t for f in self.findings for _, t in f.evidence)
        for secret in ["lab-enable-1", "lab-admin-1", "08243C4F1C5A0A16",
                       "lab-console-1", "lab-vty-1", "lab-monitor-x"]:
            self.assertNotIn(secret, text)

    def test_score_is_low(self):
        self.assertLess(netaudit.score(self.findings), 30)


class HardenedConfigTests(unittest.TestCase):
    def setUp(self):
        self.findings = audit("router_hardened.cfg")

    def test_no_high_or_medium_findings(self):
        bad = [f.id for f in self.findings if f.severity in ("HIGH", "MEDIUM")]
        self.assertEqual(bad, [])

    def test_perfect_score(self):
        self.assertEqual(netaudit.score(self.findings), 100)

    def test_banner_text_is_not_parsed_as_commands(self):
        cfg = netaudit.parse((SAMPLES / "router_hardened.cfg").read_text())
        self.assertFalse(any("Authorized access only" in b.header for b in cfg.blocks))
        self.assertTrue(cfg.top_matching(r"^banner\s+login"))


class ParserAndRedactionTests(unittest.TestCase):
    def test_children_attach_to_blocks(self):
        cfg = netaudit.parse("line vty 0 4\n login\n transport input ssh\n!\nhostname R1\n")
        vty = cfg.blocks_starting("line vty")[0]
        self.assertEqual([t for _, t in vty.children], ["login", "transport input ssh"])

    def test_redact_hides_unusual_snmp_community_but_shows_default(self):
        self.assertEqual(netaudit.redact("snmp-server community s3cr3t RO"),
                         "snmp-server community <redacted> RO")
        self.assertEqual(netaudit.redact("snmp-server community public RO"),
                         "snmp-server community public RO")

    def test_type4_and_type5_secrets_detected(self):
        found = ids(netaudit.audit_text("enable secret 4 abc\nusername a secret 5 xyz\n"))
        self.assertIn("NA-009", found)
        self.assertIn("NA-010", found)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = netaudit.main(list(args))
        return code, buf.getvalue()

    def test_fail_on_high_returns_2_for_insecure(self):
        code, _ = self.run_cli(str(SAMPLES / "router_insecure.cfg"), "--fail-on", "high")
        self.assertEqual(code, 2)

    def test_fail_on_high_returns_0_for_hardened(self):
        code, _ = self.run_cli(str(SAMPLES / "router_hardened.cfg"), "--fail-on", "high")
        self.assertEqual(code, 0)

    def test_json_output_is_valid(self):
        import json
        code, out = self.run_cli(str(SAMPLES / "router_insecure.cfg"), "-f", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data[0]["counts"]["HIGH"], 6)

    def test_missing_file_returns_1(self):
        code, _ = self.run_cli("does-not-exist.cfg")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
