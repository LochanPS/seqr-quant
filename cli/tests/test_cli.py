"""
CLI tests — uses Click test runner, no network required.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from seqr.cli import main
from seqr._scanner import SshScanResult

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE_DIR = str(FIXTURES / "sample_project_python")
SAFE_DIR = str(FIXTURES / "sample_project_safe")


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# scan ssh / mail (LITE protocol breadth)
# ---------------------------------------------------------------------------

def test_scan_ssh_help_registered(runner):
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "ssh" in result.output
    assert "mail" in result.output


def test_scan_ssh_renders_pqc(runner):
    fake = SshScanResult(
        host="example.com", port=22, reachable=True,
        server_banner="SSH-2.0-OpenSSH_9.6",
        kex_algorithms=["mlkem768x25519-sha256", "curve25519-sha256"],
        host_key_algorithms=["ssh-ed25519", "rsa-sha2-512"],
        pqc_kex_supported=True, pqc_kex_methods=["mlkem768x25519-sha256"],
        host_key_quantum_status="vulnerable",
    )
    with patch("seqr._scanner.scan_ssh", return_value=fake):
        result = runner.invoke(main, ["scan", "ssh", "example.com"])
    assert result.exit_code == 0
    assert "PQC key exchange: YES" in result.output
    assert "mlkem768x25519-sha256" in result.output


def test_scan_ssh_unreachable(runner):
    fake = SshScanResult(host="nope.example", port=22, reachable=False, error_message="timed out")
    with patch("seqr._scanner.scan_ssh", return_value=fake):
        result = runner.invoke(main, ["scan", "ssh", "nope.example"])
    assert result.exit_code == 0
    assert "timed out" in result.output


# ---------------------------------------------------------------------------
# scan code
# ---------------------------------------------------------------------------

def test_scan_code_detects_rsa(runner):
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR])
    assert result.exit_code == 0
    assert "RSA" in result.output or "ECDSA" in result.output


def test_scan_code_json_output(runner):
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "findings" in data
    assert data["summary"]["components_found"] > 0


def test_scan_code_json_has_required_fields(runner):
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--output", "json"])
    data = json.loads(result.output)
    assert "seqr_version" in data
    assert "scan_timestamp" in data
    assert "summary" in data
    summary = data["summary"]
    for key in ("files_scanned", "components_found", "critical", "high", "medium", "low"):
        assert key in summary


def test_scan_code_sarif_output(runner):
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--output", "sarif"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert len(data["runs"]) == 1
    assert "results" in data["runs"][0]


def test_fail_on_critical_exits_1_when_findings(runner):
    """Fixture has RSA (risk=8 → high). Use --fail-on high to guarantee exit 1."""
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--fail-on", "high", "--quiet"])
    assert result.exit_code == 1


def test_fail_on_critical_exits_0_when_no_findings(runner):
    """Safe fixture has no findings — --fail-on critical must exit 0."""
    result = runner.invoke(main, ["scan", "code", SAFE_DIR, "--fail-on", "critical", "--quiet"])
    assert result.exit_code == 0


def test_clean_project_exits_0(runner):
    result = runner.invoke(main, ["scan", "code", SAFE_DIR])
    assert result.exit_code == 0
    assert "0 findings" in result.output or "No issues found" in result.output


def test_scan_code_severity_filter_hides_lower(runner):
    """--severity critical should hide high findings → 0 displayed for fixture."""
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--severity", "critical"])
    assert result.exit_code == 0
    # No critical in fixture (RSA is high risk=8), so no panel printed
    assert "CRITICAL" not in result.output or "0)" in result.output


def test_scan_code_save_json(runner, tmp_path):
    out_file = tmp_path / "results.json"
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--output", "json", "--save", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert "findings" in data


def test_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def test_config_show(runner):
    result = runner.invoke(main, ["config", "show"])
    assert result.exit_code == 0
    assert "scan" in result.output or "auth" in result.output


def test_config_patterns(runner):
    result = runner.invoke(main, ["config", "patterns"])
    assert result.exit_code == 0
    assert "python" in result.output


# ---------------------------------------------------------------------------
# fail-on edge cases
# ---------------------------------------------------------------------------

def test_fail_on_with_no_findings_exits_0(runner):
    result = runner.invoke(main, ["scan", "code", SAFE_DIR, "--fail-on", "high"])
    assert result.exit_code == 0


def test_fail_on_low_exits_1_for_any_finding(runner):
    result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--fail-on", "low", "--quiet"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# scan domain — batch file, fail-on
# ---------------------------------------------------------------------------

class TestScanDomain:
    """Domain scan tests — mock the network scanner to avoid internet."""

    @pytest.fixture
    def mock_domain_result(self):
        """A mock DomainScanResult for a vulnerable RSA domain."""
        from unittest.mock import MagicMock
        r = MagicMock()
        r.domain = "example.com"
        r.port = 443
        r.reachable = True
        r.tls_version = "TLS_1_2"
        r.final_algorithm_risk = 8
        r.hndl_risk = True
        r.pqc_hybrid_offered = False
        r.error_message = None
        r.cert = MagicMock()
        r.cert.algorithm = "RSA"
        r.key_exchange_algorithm = "ECDHE"
        r.recommended_algorithm_cert = "ML-DSA-65"
        r.recommended_fips_cert = "FIPS 204"
        r.recommended_algorithm_kex = "ML-KEM-768"
        r.recommended_fips_kex = "FIPS 203"
        r.hybrid_status = "none"
        r.cdn_detected = False
        r.cdn_provider = ""
        r.scan_confidence = "high"
        return r

    def test_scan_domain_no_args_fails(self, runner):
        result = runner.invoke(main, ["scan", "domain"])
        assert result.exit_code != 0

    def test_scan_domain_from_file(self, runner, tmp_path, mock_domain_result):
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("example.com\n# a comment\n\ntest.com\n")

        mock_domain_result2 = type(mock_domain_result)()
        mock_domain_result2.domain = "test.com"
        mock_domain_result2.port = 443
        mock_domain_result2.reachable = False
        mock_domain_result2.error_message = "Connection refused"

        from unittest.mock import patch, MagicMock
        with patch("seqr._scanner.NetworkScanner.scan_domains",
                   return_value=[mock_domain_result]) as m, \
             patch("seqr._scanner.NetworkScanner.scan_domain",
                   side_effect=[mock_domain_result, mock_domain_result2]):
            result = runner.invoke(main, ["scan", "domain", "--file", str(domains_file)])

        assert result.exit_code == 0

    def test_scan_domain_file_skips_comments_and_blanks(self, runner, tmp_path, mock_domain_result):
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("# skip me\n\nexample.com\n")

        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains",
                   return_value=[mock_domain_result]) as m, \
             patch("seqr._scanner.NetworkScanner.scan_domain",
                   return_value=mock_domain_result):
            result = runner.invoke(main, ["scan", "domain", "--file", str(domains_file)])

        assert result.exit_code == 0

    def test_scan_domain_positional_still_works(self, runner, mock_domain_result):
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains",
                   return_value=[mock_domain_result]):
            result = runner.invoke(main, ["scan", "domain", "example.com"])
        assert result.exit_code == 0

    def test_scan_domain_fail_on_high_exits_1(self, runner, mock_domain_result):
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains",
                   return_value=[mock_domain_result]):
            result = runner.invoke(main, ["scan", "domain", "example.com", "--fail-on", "high"])
        assert result.exit_code == 1

    def test_scan_domain_fail_on_critical_exits_0_for_high_risk(self, runner, mock_domain_result):
        """RSA risk=8 → high, not critical. --fail-on critical should exit 0."""
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains",
                   return_value=[mock_domain_result]):
            result = runner.invoke(main, ["scan", "domain", "example.com", "--fail-on", "critical"])
        assert result.exit_code == 0

    def test_scan_domain_json_output(self, runner, mock_domain_result):
        from unittest.mock import patch
        mock_domain_result.tls_version = "TLS_1_2"
        mock_domain_result.cert.algorithm = "RSA"
        mock_domain_result.key_exchange_algorithm = "ECDHE"
        mock_domain_result.pqc_hybrid_offered = False
        mock_domain_result.recommended_fips_cert = "FIPS 204"
        mock_domain_result.recommended_fips_kex = "FIPS 203"
        with patch("seqr._scanner.NetworkScanner.scan_domains",
                   return_value=[mock_domain_result]):
            result = runner.invoke(main, ["scan", "domain", "example.com", "--output", "json"])
        assert result.exit_code == 0
        import json
        data = json.loads(result.output)
        assert "results" in data
        assert "seqr_version" in data


# ---------------------------------------------------------------------------
# New format + HNDL + shelf-life tests
# ---------------------------------------------------------------------------

def _make_domain_mock(
    domain="example.com",
    kex="ECDHE",
    cert_algo="RSA-2048",
    quantum_status="vulnerable",
    hybrid_status="none",
    hndl_risk=False,
    risk_score=7,
    data_shelf_life="short",
    cdn_detected=False,
    tls_version="TLS_1_2",
    threat_timeline="planned",
    reachable=True,
):
    from unittest.mock import MagicMock
    r = MagicMock()
    r.domain = domain
    r.port = 443
    r.reachable = reachable
    r.tls_version = tls_version
    r.final_algorithm_risk = risk_score
    r.hndl_risk = hndl_risk
    r.pqc_hybrid_offered = hybrid_status != "none"
    r.error_message = None
    r.cert = MagicMock()
    r.cert.algorithm = cert_algo.split("-")[0]
    r.key_exchange_algorithm = kex
    r.cert_algorithm = cert_algo
    r.quantum_status = quantum_status
    r.hybrid_status = hybrid_status
    r.threat_timeline = threat_timeline
    r.data_shelf_life = data_shelf_life
    r.cert_expired = False
    r.cdn_detected = cdn_detected          # explicit bool — not MagicMock
    r.cdn_provider = "Cloudflare" if cdn_detected else ""
    r.recommended_algorithm_cert = "ML-DSA-65"
    r.recommended_fips_cert = "FIPS 204"
    r.recommended_algorithm_kex = "ML-KEM-768"
    r.recommended_fips_kex = "FIPS 203"
    r.client_readiness = None
    r.scan_duration_seconds = 0.5
    # key_exchange_classification must be a real bool/attr, not MagicMock,
    # for the shelf-life override path in cli.py
    r.key_exchange_classification = MagicMock()
    r.key_exchange_classification.hndl_candidate = True
    r.key_exchange_classification.quantum_status = "vulnerable"
    return r


class TestNewDomainFormat:

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_rsa_kex_recommendation_says_replace_not_add(self, runner):
        """RSA key exchange + --verbose → 'Replace RSA' in remediation section."""
        r = _make_domain_mock(kex="RSA", cert_algo="RSA-2048")
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", "example.com", "--verbose"])
        assert result.exit_code == 0
        assert "Replace RSA" in result.output

    def test_x25519_kex_recommendation_says_add_hybrid(self, runner):
        """X25519 key exchange + --verbose → 'X25519Kyber768' in remediation section."""
        r = _make_domain_mock(kex="X25519", cert_algo="ECDSA-P256")
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", "google.com", "--verbose"])
        assert result.exit_code == 0
        assert "X25519Kyber768" in result.output

    def test_shelf_life_flag_accepted(self, runner):
        """--shelf-life long is accepted without error."""
        r = _make_domain_mock(kex="RSA")
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", "example.com", "--shelf-life", "long"])
        assert result.exit_code == 0

    def test_cdn_warning_appears_when_cdn_detected_true(self, runner):
        """cdn_detected=True (literal bool) → CDN warning in output."""
        r = _make_domain_mock(cdn_detected=True)
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", "google.com"])
        assert result.exit_code == 0
        assert "CDN" in result.output
        assert "Cloudflare" in result.output

    def test_summary_shows_scan_count_for_two_domains(self, runner):
        """SCAN SUMMARY section shown for 2-domain scan with correct counts."""
        r1 = _make_domain_mock(domain="a.example.com", quantum_status="vulnerable")
        r2 = _make_domain_mock(domain="b.example.com", quantum_status="vulnerable")
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r1, r2]):
            result = runner.invoke(main, ["scan", "domain", "a.example.com", "b.example.com"])
        assert result.exit_code == 0
        assert "SCAN SUMMARY" in result.output
        assert "2" in result.output

    def test_safe_domain_shows_quantum_safe_message(self, runner):
        """quantum_status=safe → 'QUANTUM READY' status."""
        r = _make_domain_mock(
            kex="ML-KEM-768",
            cert_algo="ML-DSA-65",
            quantum_status="safe",
            hybrid_status="full_pqc",
            risk_score=0,
        )
        from unittest.mock import patch
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", "safe.example.com"])
        assert result.exit_code == 0
        assert "QUANTUM READY" in result.output


# ---------------------------------------------------------------------------
# Fix 1-4 terminal output tests
# ---------------------------------------------------------------------------

def _run_cli_scan_with(runner, **overrides):
    """Build a domain mock, apply overrides, run CLI, return output string."""
    from unittest.mock import patch
    r = _make_domain_mock()
    for k, v in overrides.items():
        setattr(r, k, v)
    with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
        result = runner.invoke(main, ["scan", "domain", r.domain])
    return result.output


class TestTerminalFixes:

    @pytest.fixture
    def runner(self):
        return CliRunner()

    # Fix 1 — WHAT IS SECURE section (verbose only in redesign)
    def test_tls13_shows_positive_findings_section(self, runner):
        """TLS 1.3 + X25519 + --verbose → WHAT IS SECURE section with checkmarks."""
        from unittest.mock import patch
        r = _make_domain_mock(tls_version="TLS_1_3", kex="X25519")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain, "--verbose"])
        assert result.exit_code == 0
        assert "WHAT IS SECURE" in result.output
        assert "TLS 1.3" in result.output

    def test_tls10_hides_positive_findings_section(self, runner):
        """TLS 1.0 (deprecated) → WHAT IS SECURE section must NOT appear."""
        output = _run_cli_scan_with(runner, tls_version="TLS_1_0")
        assert "WHAT IS SECURE" not in output

    # Fix 3 — additional header fields and panels
    def test_cdn_detected_shows_cdn_notice_panel(self, runner):
        """cdn_detected=True → CDN name and warning in compact header box."""
        output = _run_cli_scan_with(
            runner,
            cdn_detected=True,
            cdn_provider="cloudflare",
        )
        assert "CDN" in output
        assert "cloudflare" in output.lower()

    def test_scan_error_shows_error_panel(self, runner):
        """Unreachable domain with scan_outcome → Scan Error panel with reason."""
        from unittest.mock import MagicMock, patch
        r = MagicMock()
        r.domain = "bad.example.com"
        r.port = 443
        r.reachable = False
        r.scan_outcome = "timeout"
        r.error_message = "Connection timed out"
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", "bad.example.com"])
        assert result.exit_code == 0
        assert "Scan Error" in result.output
        assert "timeout" in result.output.lower() or "timed out" in result.output.lower()

    def test_ip_scanned_shown_in_output(self, runner):
        """ip_address_scanned → visible in EVIDENCE OBSERVED with --verbose."""
        from unittest.mock import patch
        r = _make_domain_mock()
        r.ip_address_scanned = "1.2.3.4"
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain, "--verbose"])
        assert result.exit_code == 0
        assert "1.2.3.4" in result.output

    # Fix 4 — enhanced summary
    def test_summary_shows_after_multiple_domains(self, runner):
        """Two domains → SCAN SUMMARY section with domain count = 2."""
        from unittest.mock import patch
        r1 = _make_domain_mock(domain="a.com")
        r2 = _make_domain_mock(domain="b.com")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r1, r2]):
            result = runner.invoke(main, ["scan", "domain", "a.com", "b.com"])
        assert result.exit_code == 0
        assert "SCAN SUMMARY" in result.output
        assert "Domains scanned:       2" in result.output


# ---------------------------------------------------------------------------
# Terminal redesign tests (compact default + --verbose)
# ---------------------------------------------------------------------------

class TestTerminalRedesign:

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_default_output_under_20_lines(self, runner):
        """Default mode: ≤ 20 non-blank lines per domain (excluding banner)."""
        from unittest.mock import patch
        r = _make_domain_mock(tls_version="TLS_1_3")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain])
        assert result.exit_code == 0
        lines = result.output.split("\n")
        non_blank = [
            l for l in lines
            if l.strip()
            and "SeQr PQC Scanner" not in l
            and "Scanning:" not in l
        ]
        assert len(non_blank) <= 20, f"Got {len(non_blank)} non-blank domain lines"

    def test_quantum_fail_not_in_output(self, runner):
        """'QUANTUM: FAIL' must never appear — use 'MIGRATION REQUIRED' instead."""
        from unittest.mock import patch
        r = _make_domain_mock(quantum_status="vulnerable")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain])
        assert "QUANTUM: FAIL" not in result.output
        assert "MIGRATION REQUIRED" in result.output

    def test_adopt_immediately_not_in_output(self, runner):
        """'adopt immediately' must not appear in default output."""
        from unittest.mock import patch
        r = _make_domain_mock(quantum_status="vulnerable", threat_timeline="planned")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain])
        assert "adopt immediately" not in result.output.lower()

    def test_critical_not_shown_for_planned(self, runner):
        """PLANNED timeline domain must not show 'CRITICAL' — downgraded to HIGH."""
        from unittest.mock import patch
        r = _make_domain_mock(
            risk_score=10,
            threat_timeline="planned",
            data_shelf_life="permanent",
        )
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain])
        assert result.exit_code == 0
        assert "CRITICAL" not in result.output

    def test_cnsa_not_in_default_output(self, runner):
        """CNSA must not appear in default output (US federal, not applicable here)."""
        from unittest.mock import patch
        r = _make_domain_mock(quantum_status="vulnerable")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain])
        assert "CNSA" not in result.output

    def test_verbose_shows_evidence_section(self, runner):
        """--verbose must show EVIDENCE OBSERVED section."""
        from unittest.mock import patch
        r = _make_domain_mock()
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain, "--verbose"])
        assert result.exit_code == 0
        assert "EVIDENCE OBSERVED" in result.output


# ---------------------------------------------------------------------------
# FIX 3 — CI/CD --policy flag
# ---------------------------------------------------------------------------

class TestPolicyFlag:

    @pytest.fixture
    def runner(self):
        return CliRunner()

    # ── scan code ─────────────────────────────────────────────────────────

    def test_policy_strict_exits_1_for_high_severity(self, runner):
        """strict = fail on high+; fixture has RSA (risk=8 → high) → exit 1."""
        result = runner.invoke(
            main, ["scan", "code", VULNERABLE_DIR, "--policy", "strict", "--quiet"]
        )
        assert result.exit_code == 1

    def test_policy_lax_exits_0_for_high_severity(self, runner):
        """lax = fail on critical only; RSA risk=8 → high, NOT critical → exit 0."""
        result = runner.invoke(
            main, ["scan", "code", VULNERABLE_DIR, "--policy", "lax", "--quiet"]
        )
        assert result.exit_code == 0

    def test_policy_strict_exits_0_on_safe_project(self, runner):
        """strict on safe project → exit 0 (no findings)."""
        result = runner.invoke(
            main, ["scan", "code", SAFE_DIR, "--policy", "strict", "--quiet"]
        )
        assert result.exit_code == 0

    def test_policy_lax_exits_0_on_safe_project(self, runner):
        """lax on safe project → exit 0."""
        result = runner.invoke(
            main, ["scan", "code", SAFE_DIR, "--policy", "lax", "--quiet"]
        )
        assert result.exit_code == 0

    def test_no_policy_exits_0_even_with_findings(self, runner):
        """Default: no --policy → exit 0 regardless of findings."""
        result = runner.invoke(main, ["scan", "code", VULNERABLE_DIR, "--quiet"])
        assert result.exit_code == 0

    def test_policy_and_fail_on_both_can_trigger(self, runner):
        """Both --policy strict AND --fail-on low set → exit 1 (either fires)."""
        result = runner.invoke(
            main,
            ["scan", "code", VULNERABLE_DIR, "--policy", "strict", "--fail-on", "low", "--quiet"],
        )
        assert result.exit_code == 1

    # ── scan domain ───────────────────────────────────────────────────────

    def test_domain_policy_strict_exits_1_for_urgent(self, runner):
        """strict on URGENT domain → exit 1."""
        from unittest.mock import patch
        r = _make_domain_mock(threat_timeline="urgent")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(
                main, ["scan", "domain", r.domain, "--policy", "strict"]
            )
        assert result.exit_code == 1

    def test_domain_policy_strict_exits_1_for_immediate(self, runner):
        """strict on IMMEDIATE domain → exit 1."""
        from unittest.mock import patch
        r = _make_domain_mock(threat_timeline="immediate")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(
                main, ["scan", "domain", r.domain, "--policy", "strict"]
            )
        assert result.exit_code == 1

    def test_domain_policy_strict_exits_0_for_planned(self, runner):
        """strict on PLANNED domain → exit 0 (PLANNED is not URGENT+)."""
        from unittest.mock import patch
        r = _make_domain_mock(threat_timeline="planned")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(
                main, ["scan", "domain", r.domain, "--policy", "strict"]
            )
        assert result.exit_code == 0

    def test_domain_policy_lax_exits_0_for_urgent(self, runner):
        """lax on URGENT domain → exit 0 (lax only fails on IMMEDIATE)."""
        from unittest.mock import patch
        r = _make_domain_mock(threat_timeline="urgent")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(
                main, ["scan", "domain", r.domain, "--policy", "lax"]
            )
        assert result.exit_code == 0

    def test_domain_policy_lax_exits_1_for_immediate(self, runner):
        """lax on IMMEDIATE domain → exit 1."""
        from unittest.mock import patch
        r = _make_domain_mock(threat_timeline="immediate")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(
                main, ["scan", "domain", r.domain, "--policy", "lax"]
            )
        assert result.exit_code == 1

    def test_domain_no_policy_exits_0_for_immediate(self, runner):
        """No --policy → exit 0 even for IMMEDIATE domain (never breaks builds by default)."""
        from unittest.mock import patch
        r = _make_domain_mock(threat_timeline="immediate")
        with patch("seqr._scanner.NetworkScanner.scan_domains", return_value=[r]):
            result = runner.invoke(main, ["scan", "domain", r.domain])
        assert result.exit_code == 0

    def test_domain_policy_accepts_strict_and_lax_only(self, runner):
        """--policy with invalid value → CLI error."""
        result = runner.invoke(main, ["scan", "domain", "example.com", "--policy", "aggressive"])
        assert result.exit_code != 0
