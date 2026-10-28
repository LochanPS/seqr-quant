"""Minimal, XSW-hardened XML Signature (XML-DSig) — verify + sign, for SAML (A5 SSO).

Rolled locally rather than pulled from a native-``xmlsec`` library on purpose: the project
pins ``cryptography<43`` (sslyze 6.0), and no ``signxml`` release fits that window without
either dragging in an incompatible ``cryptography`` or a ``pyOpenSSL`` whose ``crypto.verify``
was removed. ``lxml`` + ``cryptography`` are already dependencies and are enough to verify an
enveloped RSA/ECDSA-SHA2 signature *correctly* — and doing it here lets us nail down the two
things a SAML verifier must never get wrong:

* **XXE** — the parser resolves no entities, loads no DTD, and rejects any DOCTYPE.
* **Signature wrapping (XSW)** — :func:`verify_signed_element` returns the *exact* element the
  signature covers, and refuses if that element's ``ID`` is not unique in the document or the
  reference does not point at it. Callers extract claims **only** from the returned element.

Scope: enveloped signatures (the SAML case), exclusive/inclusive C14N (with or without
comments), SHA-256/384/512 digests, and RSA-SHA256/384/512 or ECDSA-SHA256/384/512 signatures.
SHA-1 and every other legacy algorithm are rejected rather than accepted best-effort.
"""
from __future__ import annotations

import base64
import hmac
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from lxml import etree

DS = "http://www.w3.org/2000/09/xmldsig#"
_DS = "{%s}" % DS

ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

_DIGEST = {
    "http://www.w3.org/2001/04/xmlenc#sha256": hashes.SHA256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384": hashes.SHA384,
    "http://www.w3.org/2001/04/xmlenc#sha512": hashes.SHA512,
}
# Signature algorithm URI -> (hash, key kind). SHA-1 URIs are deliberately absent → rejected.
_SIG = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": (hashes.SHA256, "rsa"),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": (hashes.SHA384, "rsa"),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": (hashes.SHA512, "rsa"),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": (hashes.SHA256, "ec"),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": (hashes.SHA384, "ec"),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": (hashes.SHA512, "ec"),
}
# C14N algorithm URI -> (exclusive?, with_comments?)
_C14N = {
    "http://www.w3.org/2001/10/xml-exc-c14n#": (True, False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": (True, True),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": (False, False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": (False, True),
}
_DIGEST_URI = {v: k for k, v in _DIGEST.items()}
_RSA_SIG_URI = {
    "sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "sha384": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
}
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_SHA256_DIGEST_URI = "http://www.w3.org/2001/04/xmlenc#sha256"


class SignatureError(Exception):
    """Any XML-DSig parse / structure / verification failure."""


# --------------------------------------------------------------------------- parsing
def parse_xml(data: bytes) -> etree._Element:
    """Parse untrusted XML with entity resolution and DTD loading disabled (XXE-safe).

    Any DOCTYPE is rejected outright — SAML messages never legitimately carry one, and a
    DOCTYPE is the entry point for entity-expansion and external-entity attacks.
    """
    if isinstance(data, str):
        data = data.encode()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
    try:
        root = etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as e:
        raise SignatureError(f"malformed XML: {e}") from e
    if root.getroottree().docinfo.doctype:
        raise SignatureError("DOCTYPE is not permitted")
    return root


# --------------------------------------------------------------------- canonicalise
def _c14n(node: etree._Element, algorithm: str, inclusive_prefixes: Optional[list[str]]) -> bytes:
    try:
        exclusive, with_comments = _C14N[algorithm]
    except KeyError:
        raise SignatureError(f"unsupported canonicalization: {algorithm}")
    return etree.tostring(
        node,
        method="c14n",
        exclusive=exclusive,
        with_comments=with_comments,
        inclusive_ns_prefixes=inclusive_prefixes or None,
    )


def _inclusive_prefixes(transform_or_method: etree._Element) -> Optional[list[str]]:
    """Read an ec:InclusiveNamespaces/@PrefixList child, if the transform carries one."""
    inc = transform_or_method.find("{http://www.w3.org/2001/10/xml-exc-c14n#}InclusiveNamespaces")
    if inc is None:
        return None
    return inc.get("PrefixList", "").split() or None


def _load_cert_public_key(cert: str):
    cert = cert.strip()
    if "BEGIN CERTIFICATE" in cert:
        crt = load_pem_x509_certificate(cert.encode())
    else:
        raw = "".join(cert.split())
        crt = load_der_x509_certificate(base64.b64decode(raw))
    return crt.public_key()


# --------------------------------------------------------------------------- verify
def verify_signed_element(element: etree._Element, cert: str, id_attr: str = "ID") -> None:
    """Verify the enveloped signature that covers ``element``. Raise on any failure.

    XSW defence: the signature must be an enveloped child of ``element``, its single
    Reference must point at ``element``'s own ``ID``, and that ``ID`` must be unique across
    the whole document. A signature validly covering *some other* element does not count.
    """
    sig = element.find(f"./{_DS}Signature")
    if sig is None:
        raise SignatureError("element is not signed (no enveloped ds:Signature child)")

    signed_info = sig.find(f"{_DS}SignedInfo")
    if signed_info is None:
        raise SignatureError("signature has no SignedInfo")

    refs = signed_info.findall(f"{_DS}Reference")
    if len(refs) != 1:
        raise SignatureError("SignedInfo must reference exactly one element")
    ref = refs[0]

    el_id = element.get(id_attr)
    uri = (ref.get("URI") or "").lstrip("#")
    if not el_id or uri != el_id:
        raise SignatureError("signature does not reference this element (possible wrapping)")

    # Duplicate-ID wrapping: the referenced ID must resolve to exactly this element.
    root = element.getroottree().getroot()
    same_id = [e for e in root.iter() if e.get(id_attr) == el_id]
    if len(same_id) != 1 or same_id[0] is not element:
        raise SignatureError("referenced ID is not unique (possible signature wrapping)")

    # ---- 1. digest of the referenced content --------------------------------
    transforms = ref.find(f"{_DS}Transforms")
    transform_algs = (
        [t.get("Algorithm") for t in transforms.findall(f"{_DS}Transform")] if transforms is not None else []
    )
    if ENVELOPED not in transform_algs:
        raise SignatureError("reference is missing the enveloped-signature transform")
    c14n_alg = next((a for a in transform_algs if a in _C14N), None)
    if c14n_alg is None:
        raise SignatureError("reference has no supported canonicalization transform")
    inc_prefixes = None
    if transforms is not None:
        for t in transforms.findall(f"{_DS}Transform"):
            if t.get("Algorithm") == c14n_alg:
                inc_prefixes = _inclusive_prefixes(t)

    digest_method = ref.find(f"{_DS}DigestMethod")
    digest_value_el = ref.find(f"{_DS}DigestValue")
    if digest_method is None or digest_value_el is None:
        raise SignatureError("reference is missing DigestMethod/DigestValue")
    digest_alg = digest_method.get("Algorithm")
    if digest_alg not in _DIGEST:
        raise SignatureError(f"unsupported digest algorithm: {digest_alg}")

    # Apply the enveloped transform on a copy: remove *this* signature, then canonicalise.
    signed_copy = _copy_without_signature(element)
    canon = _c14n(signed_copy, c14n_alg, inc_prefixes)
    expected = base64.b64decode((digest_value_el.text or "").strip())
    actual = _hash(canon, _DIGEST[digest_alg])
    if not hmac.compare_digest(expected, actual):
        raise SignatureError("digest mismatch — signed content was altered")

    # ---- 2. signature over SignedInfo ---------------------------------------
    c14n_method_el = signed_info.find(f"{_DS}CanonicalizationMethod")
    if c14n_method_el is None:
        raise SignatureError("SignedInfo has no CanonicalizationMethod")
    si_c14n_alg = c14n_method_el.get("Algorithm")
    si_inc = _inclusive_prefixes(c14n_method_el)
    signed_info_canon = _c14n(signed_info, si_c14n_alg, si_inc)

    sig_method_el = signed_info.find(f"{_DS}SignatureMethod")
    sig_alg = sig_method_el.get("Algorithm") if sig_method_el is not None else None
    if sig_alg not in _SIG:
        raise SignatureError(f"unsupported signature algorithm: {sig_alg}")
    hash_cls, kind = _SIG[sig_alg]

    sig_value_el = sig.find(f"{_DS}SignatureValue")
    if sig_value_el is None or not (sig_value_el.text or "").strip():
        raise SignatureError("signature has no SignatureValue")
    signature = base64.b64decode("".join((sig_value_el.text or "").split()))

    public_key = _load_cert_public_key(cert)
    try:
        if kind == "rsa":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise SignatureError("RSA signature but certificate key is not RSA")
            public_key.verify(signature, signed_info_canon, padding.PKCS1v15(), hash_cls())
        else:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise SignatureError("ECDSA signature but certificate key is not EC")
            # XML-DSig ECDSA is raw r||s (IEEE P1363); cryptography wants DER.
            n = len(signature) // 2
            r = int.from_bytes(signature[:n], "big")
            s = int.from_bytes(signature[n:], "big")
            der = asym_utils.encode_dss_signature(r, s)
            public_key.verify(der, signed_info_canon, ec.ECDSA(hash_cls()))
    except InvalidSignature as e:
        raise SignatureError("signature verification failed") from e


def _copy_without_signature(element: etree._Element) -> etree._Element:
    """Deep-copy ``element`` and drop its enveloped signature (the enveloped transform).

    ``findall`` with a bare tag matches only direct children, so a signature nested deeper
    (e.g. a signed Assertion inside a signed Response) is left intact — only the signature
    that envelopes *this* element is removed, exactly as the enveloped-signature transform
    specifies. Serialising and re-parsing yields an independent tree that still carries the
    namespaces inherited from ``element``'s ancestors.
    """
    clone = etree.fromstring(etree.tostring(element))
    for child in clone.findall(f"{_DS}Signature"):
        clone.remove(child)
    return clone


def _hash(data: bytes, hash_cls) -> bytes:
    h = hashes.Hash(hash_cls())
    h.update(data)
    return h.finalize()


def verify_any_signed(root: etree._Element, cert: str, candidates: list[etree._Element],
                      id_attr: str = "ID") -> set[str]:
    """Verify every candidate that carries an enveloped signature; return their verified IDs.

    Candidates without a signature are skipped (the caller decides whether an unsigned
    element is acceptable); a candidate *with* a signature that fails verification raises.
    """
    verified: set[str] = set()
    for el in candidates:
        if el.find(f"./{_DS}Signature") is not None:
            verify_signed_element(el, cert, id_attr)
            eid = el.get(id_attr)
            if eid:
                verified.add(eid)
    return verified


# ----------------------------------------------------------------------------- sign
def sign_element(element: etree._Element, private_key_pem: bytes, cert_pem: str,
                 id_attr: str = "ID", insert_after: Optional[str] = None) -> etree._Element:
    """Enveloped-sign ``element`` in place (RSA-SHA256, exclusive C14N). Returns ``element``.

    Used by SP-side flows that need a signed message and by the test-suite to produce
    genuine signatures for the verifier. ``insert_after`` is a namespaced tag (e.g. the SAML
    Issuer) that the Signature must follow to stay schema-valid.
    """
    el_id = element.get(id_attr)
    if not el_id:
        raise SignatureError("cannot sign an element without an ID")

    # Digest of the enveloped, canonicalised element (no signature present yet).
    canon = _c14n(element, _EXC_C14N, None)
    digest_value = base64.b64encode(_hash(canon, hashes.SHA256)).decode()

    signed_info = etree.SubElement(etree.Element(f"{_DS}Signature", nsmap={"ds": DS}), f"{_DS}SignedInfo")
    sig = signed_info.getparent()
    etree.SubElement(signed_info, f"{_DS}CanonicalizationMethod", Algorithm=_EXC_C14N)
    etree.SubElement(signed_info, f"{_DS}SignatureMethod", Algorithm=_RSA_SIG_URI["sha256"])
    ref = etree.SubElement(signed_info, f"{_DS}Reference", URI=f"#{el_id}")
    transforms = etree.SubElement(ref, f"{_DS}Transforms")
    etree.SubElement(transforms, f"{_DS}Transform", Algorithm=ENVELOPED)
    etree.SubElement(transforms, f"{_DS}Transform", Algorithm=_EXC_C14N)
    etree.SubElement(ref, f"{_DS}DigestMethod", Algorithm=_SHA256_DIGEST_URI)
    dv = etree.SubElement(ref, f"{_DS}DigestValue")
    dv.text = digest_value

    # Sign the canonicalised SignedInfo.
    signed_info_canon = _c14n(signed_info, _EXC_C14N, None)
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = key.sign(signed_info_canon, padding.PKCS1v15(), hashes.SHA256())
    sv = etree.SubElement(sig, f"{_DS}SignatureValue")
    sv.text = base64.b64encode(signature).decode()

    key_info = etree.SubElement(sig, f"{_DS}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{_DS}X509Data")
    x509_cert = etree.SubElement(x509_data, f"{_DS}X509Certificate")
    x509_cert.text = _cert_body(cert_pem)

    # Place the signature (after Issuer for SAML, else first) inside the element.
    pos = 0
    if insert_after:
        for i, child in enumerate(element):
            if child.tag == insert_after:
                pos = i + 1
                break
    element.insert(pos, sig)
    return element


def _cert_body(cert_pem: str) -> str:
    lines = [ln for ln in cert_pem.strip().splitlines() if "CERTIFICATE" not in ln]
    return "".join(lines)
