"""pqcmap.tls — honest capability report + a hardened, never-failing client context."""
import ssl

from pqcmap import tls
from pqcmap.tls.context import PQC_HYBRID_GROUP, TLSCapabilities


def test_capabilities_reports_runtime_truthfully():
    caps = tls.capabilities()
    assert isinstance(caps, TLSCapabilities)
    assert caps.openssl_version.startswith("OpenSSL")
    # set_groups exists only on Python 3.13+; report must match reality.
    assert caps.can_configure_groups == hasattr(ssl.SSLContext, "set_groups")
    # pqc_maybe_default must track the linked OpenSSL major/minor.
    assert caps.pqc_maybe_default == (ssl.OPENSSL_VERSION_INFO >= (3, 5))
    assert PQC_HYBRID_GROUP in caps.candidate_groups
    assert caps.notes  # always explains itself


def test_build_client_context_returns_secure_context():
    ctx, caps = tls.build_client_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert isinstance(caps, TLSCapabilities)


def test_context_never_fails_without_pqc_support():
    # Degrading to classical TLS must never raise — PQC is best-effort.
    ctx, caps = tls.build_client_context(prefer_pqc=True)
    # If the runtime cannot pin groups, the report says so honestly.
    if not caps.can_configure_groups:
        assert caps.pqc_group_configured is False
        assert caps.configured_group is None
    # hybrid_available reflects either a configured group or an OpenSSL-3.5 default.
    assert caps.pqc_hybrid_available == (
        caps.pqc_group_configured or caps.pqc_maybe_default
    )


def test_verify_false_disables_checks_for_local_testing():
    ctx, _ = tls.build_client_context(verify=False)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


def test_capabilities_on_context_matches_builder():
    ctx, caps = tls.build_client_context()
    again = tls.capabilities(ctx)
    assert again.pqc_group_configured == caps.pqc_group_configured
    assert again.configured_group == caps.configured_group


def test_summary_and_report_are_nonempty_strings():
    assert tls.report()
    assert "PQC-hybrid TLS" in tls.capabilities().summary()
    assert isinstance(tls.capabilities().as_dict(), dict)
