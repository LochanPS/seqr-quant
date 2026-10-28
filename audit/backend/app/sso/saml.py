"""SAML 2.0 SP engine (A5 SSO) — AuthnRequest, Response validation, identity, SLO.

Mirrors :mod:`app.sso.oidc`: multi-tenant (each org configures its own
:class:`app.models.saml_provider.SAMLProvider`), SP-initiated only, and the security-critical
work — signature + audience + recipient + time-window + replay + InResponseTo — happens here
before any account is touched. Signature verification is delegated to :mod:`app.sso.xmldsig`
(XXE- and XSW-hardened); this module owns the SAML *semantics*.

Bindings: HTTP-Redirect for the AuthnRequest (and LogoutRequest), HTTP-POST for the ACS. The
``RelayState`` is a short-lived signed JWT carrying the provider id and the AuthnRequest ID, so
the ACS can bind the response to the request it issued (``InResponseTo``) and reject unsolicited
or cross-provider responses. IdP-initiated SSO is deliberately not accepted.
"""
from __future__ import annotations

import base64
import secrets
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from jose import JWTError, jwt
from lxml import etree

from app.config import settings
from app.sso import xmldsig

SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "{%s}" % SAML
_SAMLP = "{%s}" % SAMLP

NAMEID_EMAIL = "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"

_RELAY_TTL = 600  # seconds a SAML login attempt stays valid
_CLOCK_SKEW = timedelta(seconds=120)  # tolerance for IdP/SP clock drift on time windows

# Role strength — mirrors app.sso.oidc; the strongest role a user's groups grant wins.
_ROLE_RANK = {"viewer": 0, "member": 1, "auditor": 1, "analyst": 2, "admin": 3}


class SAMLError(Exception):
    """Any failure in the SAML flow (config, parsing, or assertion validation)."""


class Identity:
    """Validated result of a SAML Response — safe to act on."""

    def __init__(self, email, name_id, groups, assertion_id, session_index, not_on_or_after, name):
        self.email = email
        self.name_id = name_id
        self.groups = groups
        self.assertion_id = assertion_id
        self.session_index = session_index
        self.not_on_or_after = not_on_or_after  # for the replay-cache TTL
        self.name = name


# ------------------------------------------------------------------ RelayState (CSRF)
def make_relay_state(provider_id: uuid.UUID, request_id: str, next_url: str | None = None) -> str:
    return jwt.encode(
        {
            "type": "saml_relay",
            "pid": str(provider_id),
            "rid": request_id,
            "next": next_url,
            "exp": datetime.now(timezone.utc) + timedelta(seconds=_RELAY_TTL),
        },
        settings.SECRET_KEY,
        algorithm="HS256",
    )


def read_relay_state(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError as e:
        raise SAMLError("Invalid or expired SAML RelayState") from e
    if payload.get("type") != "saml_relay":
        raise SAMLError("Invalid RelayState type")
    return payload


# ------------------------------------------------------------------------- time utils
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError as e:
        raise SAMLError(f"invalid SAML timestamp: {value}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _text(el) -> str | None:
    return el.text.strip() if el is not None and el.text else None


# --------------------------------------------------------------- SP-initiated request
def sp_entity_id(provider, acs_base: str) -> str:
    return provider.sp_entity_id or f"{acs_base.rstrip('/')}/api/v1/saml/metadata?provider_id={provider.id}"


def build_authn_request(provider, acs_url: str, issuer: str) -> tuple[str, str]:
    """Return ``(request_id, redirect_url)`` for the HTTP-Redirect binding."""
    request_id = "_" + uuid.uuid4().hex
    root = etree.Element(
        f"{_SAMLP}AuthnRequest",
        nsmap={"samlp": SAMLP, "saml": SAML},
        ID=request_id,
        Version="2.0",
        IssueInstant=_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        Destination=provider.idp_sso_url,
        ProtocolBinding=BINDING_POST,
        AssertionConsumerServiceURL=acs_url,
    )
    iss = etree.SubElement(root, f"{_SAML}Issuer")
    iss.text = issuer
    etree.SubElement(
        root, f"{_SAMLP}NameIDPolicy",
        Format=provider.name_id_format or NAMEID_EMAIL, AllowCreate="true",
    )
    xml = etree.tostring(root)
    # Raw DEFLATE (no zlib header/trailer) per the HTTP-Redirect binding.
    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    payload = co.compress(xml) + co.flush()
    encoded = base64.b64encode(payload).decode()
    query = urlencode({"SAMLRequest": encoded})
    sep = "&" if "?" in provider.idp_sso_url else "?"
    return request_id, f"{provider.idp_sso_url}{sep}{query}"


# ------------------------------------------------------------------ Response handling
def parse_and_validate_response(
    provider, saml_response_b64: str, expected_request_id: str, acs_url: str, expected_audience: str
) -> Identity:
    """Decode + fully validate a SAML Response; return the trusted :class:`Identity`.

    Raises :class:`SAMLError` on any failure. Nothing here writes state — replay dedup and
    account provisioning are the router's job (this returns the assertion id + expiry it needs).
    """
    try:
        raw = base64.b64decode(saml_response_b64, validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise SAMLError("SAMLResponse is not valid base64") from e

    root = xmldsig.parse_xml(raw)
    if etree.QName(root).localname != "Response" or etree.QName(root).namespace != SAMLP:
        raise SAMLError("root element is not a samlp:Response")

    # --- Status must be Success --------------------------------------------------
    status = root.find(f"{_SAMLP}Status/{_SAMLP}StatusCode")
    if status is None or status.get("Value") != STATUS_SUCCESS:
        code = status.get("Value") if status is not None else "missing"
        raise SAMLError(f"SAML Response status not Success ({code})")

    # --- Exactly one plaintext assertion ----------------------------------------
    if root.find(f"{_SAML}EncryptedAssertion") is not None:
        raise SAMLError("encrypted assertions are not supported")
    assertions = root.findall(f"{_SAML}Assertion")
    if len(assertions) != 1:
        raise SAMLError(f"expected exactly one Assertion, found {len(assertions)}")
    assertion = assertions[0]

    # --- Signature: assertion must be covered by a valid signature --------------
    try:
        verified_ids = xmldsig.verify_any_signed(root, provider.idp_x509_cert, [root, assertion])
    except xmldsig.SignatureError as e:
        raise SAMLError(f"signature verification failed: {e}") from e
    assertion_signed = assertion.get("ID") in verified_ids
    response_signed = root.get("ID") in verified_ids
    if provider.want_assertions_signed and not assertion_signed:
        raise SAMLError("assertion is not individually signed (want_assertions_signed)")
    if not assertion_signed and not response_signed:
        raise SAMLError("no valid signature covers the assertion")

    # --- Issuer -----------------------------------------------------------------
    issuer = _text(assertion.find(f"{_SAML}Issuer"))
    if issuer != provider.idp_entity_id:
        raise SAMLError("assertion Issuer does not match the configured IdP entity id")

    now = _now()

    # --- Conditions: time window + audience -------------------------------------
    cond = assertion.find(f"{_SAML}Conditions")
    if cond is None:
        raise SAMLError("assertion has no Conditions")
    nb = _parse_dt(cond.get("NotBefore"))
    noa = _parse_dt(cond.get("NotOnOrAfter"))
    if nb and now + _CLOCK_SKEW < nb:
        raise SAMLError("assertion is not yet valid (Conditions/NotBefore)")
    if noa and now - _CLOCK_SKEW >= noa:
        raise SAMLError("assertion has expired (Conditions/NotOnOrAfter)")

    audiences = [
        _text(a) for a in cond.findall(f"{_SAML}AudienceRestriction/{_SAML}Audience")
    ]
    if expected_audience not in audiences:
        raise SAMLError("assertion audience does not include this SP")

    # --- Subject confirmation (bearer): recipient + window + InResponseTo -------
    scd = assertion.find(
        f"{_SAML}Subject/{_SAML}SubjectConfirmation/{_SAML}SubjectConfirmationData"
    )
    if scd is None:
        raise SAMLError("assertion has no SubjectConfirmationData")
    if scd.get("Recipient") and scd.get("Recipient") != acs_url:
        raise SAMLError("SubjectConfirmationData Recipient does not match the ACS URL")
    scd_noa = _parse_dt(scd.get("NotOnOrAfter"))
    if scd_noa and now - _CLOCK_SKEW >= scd_noa:
        raise SAMLError("SubjectConfirmationData has expired")
    in_response_to = scd.get("InResponseTo") or root.get("InResponseTo")
    if in_response_to != expected_request_id:
        raise SAMLError("InResponseTo does not match the issued AuthnRequest (unsolicited?)")

    # --- Identity ---------------------------------------------------------------
    email, name_id, groups = extract_identity(provider, assertion)
    if not email:
        raise SAMLError("no email in NameID or the configured email attribute")

    session_index = None
    authn = assertion.find(f"{_SAML}AuthnStatement")
    if authn is not None:
        session_index = authn.get("SessionIndex")

    name_attr = _first_attr(assertion, "name") or _first_attr(assertion, "displayName")

    # Assertion NotOnOrAfter drives the replay-cache TTL; fall back to the SCD window.
    replay_until = noa or scd_noa or (now + timedelta(minutes=10))
    return Identity(email, name_id, groups, assertion.get("ID"), session_index, replay_until, name_attr)


# ----------------------------------------------------------------- identity mapping
def _attributes(assertion) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for attr in assertion.findall(f"{_SAML}AttributeStatement/{_SAML}Attribute"):
        name = attr.get("Name") or attr.get("FriendlyName")
        if not name:
            continue
        values = [_text(v) for v in attr.findall(f"{_SAML}AttributeValue")]
        out[name] = [v for v in values if v]
    return out


def _first_attr(assertion, name: str) -> str | None:
    vals = _attributes(assertion).get(name)
    return vals[0] if vals else None


def extract_identity(provider, assertion) -> tuple[str | None, str | None, list[str]]:
    name_id = _text(assertion.find(f"{_SAML}Subject/{_SAML}NameID"))
    attrs = _attributes(assertion)
    if provider.email_attribute:
        vals = attrs.get(provider.email_attribute)
        email = vals[0] if vals else None
    else:
        email = name_id if (name_id and "@" in name_id) else None
    groups: list[str] = []
    if provider.groups_attribute:
        groups = attrs.get(provider.groups_attribute, [])
    return (email.lower() if email else None), name_id, [str(g) for g in groups]


def map_role(provider, groups: list[str]) -> str:
    """Map IdP groups → the strongest SeQr role they grant, else the provider default."""
    from app.rbac import VALID_ROLES

    mapped = [(provider.group_role_map or {}).get(g) for g in groups]
    valid = [r for r in mapped if r in VALID_ROLES]
    if not valid:
        return provider.default_role if provider.default_role in VALID_ROLES else "member"
    return max(valid, key=lambda r: _ROLE_RANK.get(r, 0))


# ------------------------------------------------------------------------ SP metadata
def sp_metadata_xml(entity_id: str, acs_url: str, slo_url: str | None) -> bytes:
    md = "urn:oasis:names:tc:SAML:2.0:metadata"
    _md = "{%s}" % md
    root = etree.Element(f"{_md}EntityDescriptor", nsmap={"md": md}, entityID=entity_id)
    spsso = etree.SubElement(
        root, f"{_md}SPSSODescriptor",
        AuthnRequestsSigned="false", WantAssertionsSigned="true",
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
    )
    if slo_url:
        etree.SubElement(
            spsso, f"{_md}SingleLogoutService", Binding=BINDING_REDIRECT, Location=slo_url
        )
    etree.SubElement(
        spsso, f"{_md}NameIDFormat"
    ).text = NAMEID_EMAIL
    etree.SubElement(
        spsso, f"{_md}AssertionConsumerService",
        Binding=BINDING_POST, Location=acs_url, index="0", isDefault="true",
    )
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


# ------------------------------------------------------------------------------- SLO
def build_logout_request(provider, name_id: str, session_index: str | None, issuer: str) -> tuple[str, str]:
    """SP-initiated LogoutRequest over HTTP-Redirect. Returns ``(request_id, redirect_url)``."""
    if not provider.idp_slo_url:
        raise SAMLError("this IdP has no SingleLogout URL configured")
    request_id = "_" + uuid.uuid4().hex
    root = etree.Element(
        f"{_SAMLP}LogoutRequest",
        nsmap={"samlp": SAMLP, "saml": SAML},
        ID=request_id, Version="2.0",
        IssueInstant=_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        Destination=provider.idp_slo_url,
    )
    iss = etree.SubElement(root, f"{_SAML}Issuer")
    iss.text = issuer
    nid = etree.SubElement(root, f"{_SAML}NameID", Format=provider.name_id_format or NAMEID_EMAIL)
    nid.text = name_id
    if session_index:
        si = etree.SubElement(root, f"{_SAMLP}SessionIndex")
        si.text = session_index
    xml = etree.tostring(root)
    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    payload = co.compress(xml) + co.flush()
    query = urlencode({"SAMLRequest": base64.b64encode(payload).decode()})
    sep = "&" if "?" in provider.idp_slo_url else "?"
    return request_id, f"{provider.idp_slo_url}{sep}{query}"


def build_logout_response(provider, in_response_to: str, issuer: str) -> str:
    """Build a LogoutResponse (Success) for an IdP-initiated LogoutRequest, redirect-encoded."""
    root = etree.Element(
        f"{_SAMLP}LogoutResponse",
        nsmap={"samlp": SAMLP, "saml": SAML},
        ID="_" + uuid.uuid4().hex, Version="2.0",
        IssueInstant=_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        InResponseTo=in_response_to,
    )
    iss = etree.SubElement(root, f"{_SAML}Issuer")
    iss.text = issuer
    status = etree.SubElement(root, f"{_SAMLP}Status")
    etree.SubElement(status, f"{_SAMLP}StatusCode", Value=STATUS_SUCCESS)
    xml = etree.tostring(root)
    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    payload = co.compress(xml) + co.flush()
    return base64.b64encode(payload).decode()


def decode_redirect_message(encoded: str) -> etree._Element:
    """Inflate + parse a SAMLRequest/SAMLResponse from the HTTP-Redirect binding (XXE-safe)."""
    try:
        compressed = base64.b64decode(encoded, validate=True)
        xml = zlib.decompress(compressed, -zlib.MAX_WBITS)
    except (ValueError, zlib.error) as e:
        raise SAMLError("could not decode redirect-binding SAML message") from e
    return xmldsig.parse_xml(xml)
