"""Enterprise SSO / SAML 2.0 tests (A5).

No live IdP: assertions are signed locally with a real RSA keypair + self-signed cert via
app.sso.xmldsig, then fed through the actual ACS. This exercises the security-critical path
for real — signature (incl. tamper / wrong-cert / signature-wrapping), audience, recipient,
time windows, InResponseTo, and single-use replay — plus group→role mapping, JIT provisioning,
config CRUD, and tenancy.
"""
import base64
import datetime
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from app.routers import saml as saml_router
from app.sso import saml, xmldsig

SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "{%s}" % SAML
_SAMLP = "{%s}" % SAMLP
EMAIL_FMT = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"

IDP_ENTITY = "https://idp.example.com/entity"
IDP_SSO = "https://idp.example.com/sso"
SP_ENTITY = "https://sp.seqr.test"
ACS_URL = "http://test/api/v1/saml/acs"


# --------------------------------------------------------------------- key fixtures
@pytest.fixture(scope="module")
def idp_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return priv, cert_pem


def _wrong_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(2)
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return priv, cert.public_bytes(serialization.Encoding.PEM).decode()


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_response(
    priv, cert_pem, *, request_id, acs_url=ACS_URL, audience=SP_ENTITY, issuer=IDP_ENTITY,
    email="user@corp.com", groups=("seqr-staff",), aid=None, sign=True,
    cond_notbefore=-60, cond_notonorafter=300, subj_notonorafter=300, in_response_to=None,
    recipient=None, status=SUCCESS, extra_assertion=False,
):
    """Construct a SAMLResponse (base64) with one signed assertion, returning (b64, assertion_id)."""
    now = datetime.datetime.utcnow()
    aid = aid or ("_" + uuid.uuid4().hex)
    resp = etree.Element(
        f"{_SAMLP}Response", nsmap={"samlp": SAMLP, "saml": SAML},
        ID="_" + uuid.uuid4().hex, Version="2.0", IssueInstant=_iso(now),
        InResponseTo=request_id, Destination=acs_url,
    )
    etree.SubElement(resp, f"{_SAML}Issuer").text = issuer
    st = etree.SubElement(resp, f"{_SAMLP}Status")
    etree.SubElement(st, f"{_SAMLP}StatusCode", Value=status)

    def _assertion(assertion_id, mail):
        a = etree.SubElement(resp, f"{_SAML}Assertion", ID=assertion_id, Version="2.0", IssueInstant=_iso(now))
        etree.SubElement(a, f"{_SAML}Issuer").text = issuer
        subj = etree.SubElement(a, f"{_SAML}Subject")
        etree.SubElement(subj, f"{_SAML}NameID", Format=EMAIL_FMT).text = mail
        sc = etree.SubElement(subj, f"{_SAML}SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
        etree.SubElement(
            sc, f"{_SAML}SubjectConfirmationData",
            Recipient=recipient or acs_url,
            NotOnOrAfter=_iso(now + datetime.timedelta(seconds=subj_notonorafter)),
            InResponseTo=in_response_to or request_id,
        )
        cond = etree.SubElement(
            a, f"{_SAML}Conditions",
            NotBefore=_iso(now + datetime.timedelta(seconds=cond_notbefore)),
            NotOnOrAfter=_iso(now + datetime.timedelta(seconds=cond_notonorafter)),
        )
        ar = etree.SubElement(cond, f"{_SAML}AudienceRestriction")
        etree.SubElement(ar, f"{_SAML}Audience").text = audience
        authn = etree.SubElement(a, f"{_SAML}AuthnStatement", AuthnInstant=_iso(now), SessionIndex="_sess1")
        ac = etree.SubElement(authn, f"{_SAML}AuthnContext")
        etree.SubElement(ac, f"{_SAML}AuthnContextClassRef").text = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
        if groups is not None:
            ast = etree.SubElement(a, f"{_SAML}AttributeStatement")
            attr = etree.SubElement(ast, f"{_SAML}Attribute", Name="groups")
            for g in groups:
                etree.SubElement(attr, f"{_SAML}AttributeValue").text = g
        return a

    assertion = _assertion(aid, email)
    if extra_assertion:
        _assertion("_" + uuid.uuid4().hex, "attacker@corp.com")
    if sign:
        # Sign in place (as an IdP does), so the verifier sees the exact signed context.
        xmldsig.sign_element(assertion, priv, cert_pem, insert_after=f"{_SAML}Issuer")
    return base64.b64encode(etree.tostring(resp)).decode(), aid


# =============================================================== xmldsig unit tests
def test_parse_xml_rejects_doctype():
    xxe = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>'
    with pytest.raises(xmldsig.SignatureError):
        xmldsig.parse_xml(xxe)


def test_sign_verify_roundtrip_and_tamper(idp_keys):
    priv, cert = idp_keys
    a = etree.Element(f"{_SAML}Assertion", ID="_x1", nsmap={"saml": SAML})
    etree.SubElement(a, f"{_SAML}Issuer").text = "idp"
    etree.SubElement(a, f"{_SAML}NameID").text = "u@corp.com"
    xmldsig.sign_element(a, priv, cert, insert_after=f"{_SAML}Issuer")
    doc = xmldsig.parse_xml(etree.tostring(a))
    xmldsig.verify_signed_element(doc, cert)  # valid → no raise

    doc2 = xmldsig.parse_xml(etree.tostring(a))
    doc2.find(f".//{_SAML}NameID").text = "attacker@corp.com"
    with pytest.raises(xmldsig.SignatureError):
        xmldsig.verify_signed_element(doc2, cert)


def test_verify_rejects_duplicate_id_wrapping(idp_keys):
    """Signature-wrapping via a second element that reuses the signed element's ID."""
    priv, cert = idp_keys
    a = etree.Element(f"{_SAML}Assertion", ID="_dup", nsmap={"saml": SAML})
    etree.SubElement(a, f"{_SAML}Issuer").text = "idp"
    etree.SubElement(a, f"{_SAML}NameID").text = "u@corp.com"
    xmldsig.sign_element(a, priv, cert, insert_after=f"{_SAML}Issuer")
    # Wrap: a parent holding the signed assertion AND a decoy sharing the same ID.
    root = etree.Element(f"{_SAML}Wrapper", nsmap={"saml": SAML})
    root.append(a)
    decoy = etree.SubElement(root, f"{_SAML}Assertion", ID="_dup")
    etree.SubElement(decoy, f"{_SAML}NameID").text = "attacker@corp.com"
    reparsed = xmldsig.parse_xml(etree.tostring(root))
    signed = reparsed.find(f"{_SAML}Assertion")
    with pytest.raises(xmldsig.SignatureError):
        xmldsig.verify_signed_element(signed, cert)


def test_verify_rejects_wrong_cert(idp_keys):
    priv, cert = idp_keys
    a = etree.Element(f"{_SAML}Assertion", ID="_w1", nsmap={"saml": SAML})
    etree.SubElement(a, f"{_SAML}Issuer").text = "idp"
    etree.SubElement(a, f"{_SAML}NameID").text = "u@corp.com"
    xmldsig.sign_element(a, priv, cert, insert_after=f"{_SAML}Issuer")
    _, other = _wrong_cert()
    with pytest.raises(xmldsig.SignatureError):
        xmldsig.verify_signed_element(xmldsig.parse_xml(etree.tostring(a)), other)


# ==================================================== engine-level validation tests
def _provider(idp_keys, **over):
    priv, cert = idp_keys
    from app.models.saml_provider import SAMLProvider

    defaults = dict(
        id=uuid.uuid4(), org_id=uuid.uuid4(), idp_entity_id=IDP_ENTITY, idp_sso_url=IDP_SSO,
        idp_x509_cert=cert, sp_entity_id=SP_ENTITY, want_assertions_signed=True,
        groups_attribute="groups", group_role_map={"seqr-admins": "admin", "seqr-staff": "analyst"},
        default_role="viewer", email_attribute=None, email_domain=None, auto_provision=True,
        enabled=True, display_name="SSO", idp_slo_url=None, name_id_format=None,
    )
    defaults.update(over)
    return SAMLProvider(**defaults)


def test_validate_accepts_valid(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, aid = _build_response(priv, cert, request_id="_req1")
    ident = saml.parse_and_validate_response(p, b64, "_req1", ACS_URL, SP_ENTITY)
    assert ident.email == "user@corp.com"
    assert ident.groups == ["seqr-staff"]
    assert ident.assertion_id == aid


def test_validate_rejects_wrong_audience(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1", audience="https://someone-else")
    with pytest.raises(saml.SAMLError, match="audience"):
        saml.parse_and_validate_response(p, b64, "_req1", ACS_URL, SP_ENTITY)


def test_validate_rejects_expired(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1", cond_notbefore=-600, cond_notonorafter=-300)
    with pytest.raises(saml.SAMLError, match="expired"):
        saml.parse_and_validate_response(p, b64, "_req1", ACS_URL, SP_ENTITY)


def test_validate_rejects_bad_inresponseto(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1")
    with pytest.raises(saml.SAMLError, match="InResponseTo"):
        saml.parse_and_validate_response(p, b64, "_DIFFERENT", ACS_URL, SP_ENTITY)


def test_validate_rejects_bad_recipient(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1", recipient="http://evil/acs")
    with pytest.raises(saml.SAMLError, match="Recipient"):
        saml.parse_and_validate_response(p, b64, "_req1", ACS_URL, SP_ENTITY)


def test_validate_rejects_unsigned_assertion(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1", sign=False)
    with pytest.raises(saml.SAMLError):
        saml.parse_and_validate_response(p, b64, "_req1", ACS_URL, SP_ENTITY)


def test_validate_rejects_tampered_after_signing(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1")
    raw = base64.b64decode(b64)
    root = etree.fromstring(raw)
    root.find(f".//{_SAML}NameID").text = "attacker@corp.com"
    tampered = base64.b64encode(etree.tostring(root)).decode()
    with pytest.raises(saml.SAMLError):
        saml.parse_and_validate_response(p, tampered, "_req1", ACS_URL, SP_ENTITY)


def test_validate_rejects_multiple_assertions(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1", extra_assertion=True)
    with pytest.raises(saml.SAMLError, match="exactly one Assertion"):
        saml.parse_and_validate_response(p, b64, "_req1", ACS_URL, SP_ENTITY)


def test_validate_rejects_non_success_status(idp_keys):
    priv, cert = idp_keys
    p = _provider(idp_keys)
    b64, _ = _build_response(priv, cert, request_id="_req1",
                             status="urn:oasis:names:tc:SAML:2.0:status:Requester")
    with pytest.raises(saml.SAMLError, match="status"):
        saml.parse_and_validate_response(p, b64, "_req1", ACS_URL, SP_ENTITY)


def test_map_role_picks_strongest(idp_keys):
    p = _provider(idp_keys, group_role_map={"eng": "analyst", "sec": "admin", "ro": "viewer"})
    assert saml.map_role(p, ["eng", "sec", "ro"]) == "admin"
    assert saml.map_role(p, ["eng", "ro"]) == "analyst"
    assert saml.map_role(p, ["nope"]) == "viewer"  # default_role


# ================================================================= config CRUD / API
async def _register(client, email, org):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "SecurePass123!", "name": "T", "org_name": org},
    )
    assert r.status_code == 200
    return r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_config_crud(client, idp_keys):
    _, cert = idp_keys
    admin = await _register(client, "admin@corp.com", "Corp")
    tok = admin["access_token"]
    r = await client.put(
        "/api/v1/saml/config",
        json={"idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_x509_cert": cert,
              "group_role_map": {"seqr-admins": "admin"}, "default_role": "viewer",
              "email_domain": "Corp.COM"},
        headers=_auth(tok),
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["configured"] is True and out["email_domain"] == "corp.com"
    assert out["acs_url"].endswith("/api/v1/saml/acs")
    assert out["metadata_url"] and out["login_url"]

    g = (await client.get("/api/v1/saml/config", headers=_auth(tok))).json()
    assert g["idp_entity_id"] == IDP_ENTITY

    # metadata is public XML
    md = await client.get("/api/v1/saml/metadata", params={"provider_id": out["id"]})
    assert md.status_code == 200 and b"EntityDescriptor" in md.content


@pytest.mark.asyncio
async def test_config_rejects_invalid_role_and_non_admin(client, idp_keys):
    _, cert = idp_keys
    admin = await _register(client, "admin@corp.com", "Corp")
    tok = admin["access_token"]
    r = await client.put(
        "/api/v1/saml/config",
        json={"idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_x509_cert": cert,
              "group_role_map": {"g": "wizard"}},
        headers=_auth(tok),
    )
    assert r.status_code == 400

    inv = await client.post("/api/v1/org/users/invite", json={"email": "v@corp.com", "role": "viewer"},
                            headers=_auth(tok))
    vpw = inv.json()["temporary_password"]
    vtok = (await client.post("/api/v1/auth/login", json={"email": "v@corp.com", "password": vpw})).json()["access_token"]
    assert (await client.get("/api/v1/saml/config", headers=_auth(vtok))).status_code == 403


# ===================================================================== end-to-end ACS
async def _configure(client, tok, idp_keys, **over):
    _, cert = idp_keys
    body = {"idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_x509_cert": cert,
            "sp_entity_id": SP_ENTITY,
            "group_role_map": {"seqr-admins": "admin", "seqr-staff": "analyst"},
            "default_role": "viewer"}
    body.update(over)
    return (await client.put("/api/v1/saml/config", json=body, headers=_auth(tok))).json()


def _tokens(loc):
    frag = loc.split("#", 1)[1]
    return dict(kv.split("=", 1) for kv in frag.split("&"))


async def _post_acs(client, monkeypatch, provider_id, saml_response_b64, request_id):
    monkeypatch.setattr(saml_router.settings, "SAML_ENABLED", True)
    relay = saml.make_relay_state(uuid.UUID(provider_id), request_id)
    return await client.post(
        "/api/v1/saml/acs",
        data={"SAMLResponse": saml_response_b64, "RelayState": relay},
        follow_redirects=False,
    )


@pytest.mark.asyncio
async def test_login_requires_saml_enabled(client, idp_keys, monkeypatch):
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = await _configure(client, admin["access_token"], idp_keys, email_domain="corp.com")
    monkeypatch.setattr(saml_router.settings, "SAML_ENABLED", False)
    r = await client.get("/api/v1/saml/login", params={"provider_id": cfg["id"]})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_login_redirects_to_idp(client, idp_keys, monkeypatch):
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = await _configure(client, admin["access_token"], idp_keys)
    monkeypatch.setattr(saml_router.settings, "SAML_ENABLED", True)
    r = await client.get("/api/v1/saml/login", params={"provider_id": cfg["id"]}, follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(IDP_SSO) and "SAMLRequest=" in loc and "RelayState=" in loc


@pytest.mark.asyncio
async def test_acs_provisions_and_maps_role(client, idp_keys, monkeypatch):
    from jose import jwt as jose
    from app.config import settings as app_settings

    priv, cert = idp_keys
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = await _configure(client, admin["access_token"], idp_keys)

    b64, _ = _build_response(priv, cert, request_id="_reqA", email="newbie@corp.com", groups=("seqr-staff",))
    r = await _post_acs(client, monkeypatch, cfg["id"], b64, "_reqA")
    assert r.status_code == 302, r.text
    toks = _tokens(r.headers["location"])
    assert "access_token" in toks
    decoded = jose.decode(toks["access_token"], app_settings.SECRET_KEY, algorithms=["HS256"])
    assert decoded["role"] == "analyst"

    me = await client.get("/api/v1/org", headers=_auth(toks["access_token"]))
    assert me.status_code == 200

    # role change at the IdP is synced on next login (staff → admins), new assertion id
    b64b, _ = _build_response(priv, cert, request_id="_reqB", email="newbie@corp.com", groups=("seqr-admins",))
    r2 = await _post_acs(client, monkeypatch, cfg["id"], b64b, "_reqB")
    toks2 = _tokens(r2.headers["location"])
    assert jose.decode(toks2["access_token"], app_settings.SECRET_KEY, algorithms=["HS256"])["role"] == "admin"


@pytest.mark.asyncio
async def test_acs_rejects_replayed_assertion(client, idp_keys, monkeypatch):
    priv, cert = idp_keys
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = await _configure(client, admin["access_token"], idp_keys)

    b64, _ = _build_response(priv, cert, request_id="_reqR", email="dup@corp.com", groups=("seqr-staff",))
    r1 = await _post_acs(client, monkeypatch, cfg["id"], b64, "_reqR")
    assert r1.status_code == 302 and "access_token" in r1.headers["location"]
    # same assertion again → replay
    r2 = await _post_acs(client, monkeypatch, cfg["id"], b64, "_reqR")
    assert "error=assertion_replayed" in r2.headers["location"]


@pytest.mark.asyncio
async def test_acs_rejects_tampered_assertion(client, idp_keys, monkeypatch):
    priv, cert = idp_keys
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = await _configure(client, admin["access_token"], idp_keys)

    b64, _ = _build_response(priv, cert, request_id="_reqT", email="ok@corp.com")
    root = etree.fromstring(base64.b64decode(b64))
    root.find(f".//{_SAML}NameID").text = "attacker@corp.com"
    tampered = base64.b64encode(etree.tostring(root)).decode()
    r = await _post_acs(client, monkeypatch, cfg["id"], tampered, "_reqT")
    assert "error=assertion_validation_failed" in r.headers["location"]


@pytest.mark.asyncio
async def test_acs_rejects_cross_org_email(client, idp_keys, monkeypatch):
    priv, cert = idp_keys
    await _register(client, "shared@corp.com", "OrgOne")
    two = await _register(client, "admin@two.com", "OrgTwo")
    cfg = await _configure(client, two["access_token"], idp_keys)

    b64, _ = _build_response(priv, cert, request_id="_reqX", email="shared@corp.com", groups=())
    r = await _post_acs(client, monkeypatch, cfg["id"], b64, "_reqX")
    assert "error=email_belongs_to_other_org" in r.headers["location"]


@pytest.mark.asyncio
async def test_acs_blocks_unprovisioned_when_disabled(client, idp_keys, monkeypatch):
    priv, cert = idp_keys
    admin = await _register(client, "admin@corp.com", "Corp")
    cfg = await _configure(client, admin["access_token"], idp_keys, auto_provision=False)

    b64, _ = _build_response(priv, cert, request_id="_reqU", email="nobody@corp.com", groups=())
    r = await _post_acs(client, monkeypatch, cfg["id"], b64, "_reqU")
    assert "error=user_not_provisioned" in r.headers["location"]
