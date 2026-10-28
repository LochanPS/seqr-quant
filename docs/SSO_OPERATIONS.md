# SeQr — Enterprise SSO Operations (OIDC + SAML)

A5 enterprise table-stakes. Per-org single sign-on in **two protocols** — OpenID Connect and
SAML 2.0. An org configures its own IdP, IdP groups map to SeQr roles
([`app/rbac.py`](../audit/backend/app/rbac.py)), and users are provisioned just-in-time on
first login. Both work with Okta, Microsoft Entra ID, Google Workspace, Keycloak, Auth0, …

- **OIDC** — this section (below).
- **SAML 2.0** — see [**SAML 2.0**](#saml-20) further down.

## Enabling

Deployment-level (backend env):

| Env | Default | Meaning |
|---|---|---|
| `SSO_ENABLED` | `false` | Master switch for the login/callback flow. Config CRUD works regardless, so an admin can stage config first. |
| `OIDC_REDIRECT_BASE` | _(empty)_ | Public base URL of the backend, used to build the redirect URI. Empty = derive from the request (only safe behind a correct proxy). Set it explicitly in production. |

The **redirect URI** to register with every IdP is:

```
{OIDC_REDIRECT_BASE}/api/v1/sso/oidc/callback
```

`GET /api/v1/sso/config` returns the exact value under `redirect_uri`.

## Per-org configuration (org admin)

`org:manage` permission (admin role) required. Upsert:

```http
PUT /api/v1/sso/config
{
  "issuer": "https://acme.okta.com",
  "client_id": "0oaXXXX",
  "client_secret": "••••",            // write-only; encrypted at rest, never returned
  "scopes": "openid email profile groups",
  "groups_claim": "groups",            // the id_token claim carrying group names
  "group_role_map": {                  // IdP group  ->  SeQr role
    "seqr-admins": "admin",
    "seqr-engineers": "analyst",
    "seqr-auditors": "auditor"
  },
  "default_role": "viewer",            // when no group maps
  "email_domain": "acme.com",          // powers email-first "Sign in with SSO"
  "auto_provision": true,              // create users on first login
  "enabled": true
}
```

- The client secret is stored **encrypted** (Fernet, key derived from `SECRET_KEY` —
  [`app/sso/crypto.py`](../audit/backend/app/sso/crypto.py)) and is never serialised back.
  Omit `client_secret` on a later `PUT` to keep the existing one.
- When a user's groups map to several roles, the **strongest** wins (admin > analyst >
  auditor/member > viewer). Groups are authoritative — a user's role is re-synced from the
  IdP on **every** login.
- `GET /api/v1/sso/config` shows current config (secret redacted); `DELETE` removes it.

## Login flow

1. Frontend sends the user to `GET /api/v1/sso/oidc/start?provider_id=…` (or
   `?domain=acme.com` / `?email=user@acme.com` for the email-first path).
2. Backend 302s to the IdP authorize endpoint with a signed `state` (CSRF) + `nonce`.
3. IdP authenticates and redirects back to the callback with `code` + `state`.
4. Backend exchanges the code, **validates the id_token** (signature via the IdP JWKS,
   plus `iss` / `aud` / `exp` / `nonce`), maps groups → role, provisions/links the user,
   mints SeQr access + refresh tokens, and 302s to
   `{FRONTEND_URL}/auth/sso/callback#access_token=…&refresh_token=…&token_type=bearer`.
   Tokens travel in the URL **fragment** so they never reach server logs or `Referer`.

Errors come back as `.../auth/sso/callback#error=<reason>` (e.g. `email_belongs_to_other_org`,
`identity_mismatch`, `user_not_provisioned`, `token_validation_failed`). The frontend reads
the fragment, stores the tokens, and routes to the dashboard — or shows the error.

## Security notes

- **Identity binding:** the IdP `sub` is bound to the account on first SSO login; a later
  email change at the IdP cannot silently take over a different account (`identity_mismatch`).
- **Tenancy:** an email already belonging to another org is rejected — SSO never moves a
  user between tenants.
- **Every SSO login/provision writes an audit event** (`sso.login` / `sso.provisioned`),
  visible at `GET /api/v1/audit`.
- Rotating `SECRET_KEY` invalidates stored client secrets (and all JWTs) — re-enter the IdP
  secret after a rotation.

## Testing against a real IdP (Keycloak, quick)

1. Run Keycloak, create a realm + confidential client, set the redirect URI above, add a
   `groups` mapper to the ID token, create groups matching `group_role_map`.
2. `PUT /api/v1/sso/config` with the realm issuer (`…/realms/<realm>`), client id/secret.
3. `SSO_ENABLED=true`, restart, hit `/api/v1/sso/oidc/start?domain=<your-domain>`.

The automated suite (`tests/test_sso_oidc.py`) mints a real RS256 id_token with a local
keypair and stubs the JWKS/token HTTP calls, so the validation + mapping + provisioning
paths are covered without a live IdP.

---

# SAML 2.0

Per-org SAML 2.0 SP, mirroring OIDC (per-org config, JIT provisioning, group→role mapping,
strongest role wins, tokens minted to the same FE fragment). **SP-initiated only** — the SP
issues the AuthnRequest and binds the response to it (`InResponseTo`); IdP-initiated SSO is
not accepted (it has no request to bind to and widens the replay/forgery surface).

Bindings: **HTTP-Redirect** for the AuthnRequest, **HTTP-POST** for the assertion (ACS).

## Enabling

| Env | Default | Meaning |
|---|---|---|
| `SAML_ENABLED` | `false` | Master switch for the login/ACS/SLO flow. Config CRUD works regardless, so an admin can stage config first. |
| `SAML_ACS_BASE` | _(empty)_ | Public base URL of the backend, used to build the ACS URL, SP EntityID and metadata. Empty = derive from the request (only safe behind a correct proxy). Set explicitly in production. Mirrors `OIDC_REDIRECT_BASE`. |

Endpoints the admin registers at the IdP (all under `{SAML_ACS_BASE}`):

```
ACS (AssertionConsumerService, HTTP-POST):  /api/v1/saml/acs
SP metadata (XML):                          /api/v1/saml/metadata?provider_id=<id>
SP EntityID (default):                      the metadata URL above (override via sp_entity_id)
Single Logout service:                      /api/v1/saml/sls
```

`GET /api/v1/saml/config` returns `acs_url`, `metadata_url` and `login_url`; the metadata
endpoint serves ready-to-upload SP metadata.

## Per-org configuration (org admin)

`org:manage` (admin role) required.

```http
PUT /api/v1/saml/config
{
  "idp_entity_id": "https://acme.okta.com/exk...",   // the assertion Issuer must equal this
  "idp_sso_url":   "https://acme.okta.com/app/.../sso/saml",
  "idp_x509_cert": "MIID...==",                       // IdP signing cert, PEM or bare base64 (PUBLIC)
  "idp_slo_url":   "https://acme.okta.com/app/.../slo/saml",   // optional
  "sp_entity_id":  null,                              // optional; defaults to the metadata URL
  "want_assertions_signed": true,                     // require the Assertion itself be signed
  "email_attribute": null,                            // read email from this attr, else the NameID
  "groups_attribute": "groups",                       // SAML attribute carrying group names
  "group_role_map": { "seqr-admins": "admin", "seqr-staff": "analyst" },
  "default_role": "viewer",
  "email_domain": "acme.com",                         // email-first "Sign in with SSO"
  "auto_provision": true,
  "enabled": true
}
```

- Unlike OIDC there is **no client secret** — SAML trusts the IdP by its public signing
  certificate, stored as-is (PEM or bare base64 DER) and returned by the API.
- Group→role mapping is identical to OIDC: strongest role wins, re-synced from the IdP on
  every login.

## Login flow

1. Frontend sends the user to `GET /api/v1/saml/login?provider_id=…` (or `?domain=` / `?email=`).
2. Backend 302s to the IdP SSO URL with a DEFLATE+base64 `SAMLRequest` and a signed
   `RelayState` (a short-lived JWT carrying the provider id + AuthnRequest ID).
3. IdP authenticates and **POSTs** the `SAMLResponse` (+ `RelayState`) to the ACS.
4. Backend fully validates (see below), maps groups → role, provisions/links the user,
   dedupes the assertion, mints SeQr tokens, and 302s to
   `{FRONTEND_URL}/auth/sso/callback#access_token=…&refresh_token=…&token_type=bearer`.
   Errors come back as `#error=<reason>` (`assertion_validation_failed`, `assertion_replayed`,
   `email_belongs_to_other_org`, `identity_mismatch`, `user_not_provisioned`, …).

## Assertion validation (security-critical)

Every check is enforced before any account is touched
([`app/sso/saml.py`](../audit/backend/app/sso/saml.py) + [`app/sso/xmldsig.py`](../audit/backend/app/sso/xmldsig.py)):

- **XML parse** — entity resolution + DTD loading disabled, any DOCTYPE rejected (XXE).
- **Signature** — enveloped RSA/ECDSA-SHA-256/384/512 only (SHA-1 rejected), verified against
  the configured cert. The assertion must be covered by a valid signature; `want_assertions_signed`
  (default on) requires the Assertion element itself to be signed.
- **Signature wrapping (XSW)** — the verifier returns the exact signed element; the reference
  must point at that element and its `ID` must be unique in the document. Exactly one Assertion
  is accepted; extra/duplicate assertions are rejected.
- **Issuer** must equal `idp_entity_id`.
- **Time window** — `Conditions` NotBefore/NotOnOrAfter and the SubjectConfirmationData
  NotOnOrAfter, with a 120 s clock-skew tolerance.
- **Audience** — an `AudienceRestriction` naming this SP's EntityID is required.
- **Recipient** must equal the ACS URL; **InResponseTo** must equal the AuthnRequest we issued
  (unsolicited responses rejected).
- **Replay** — assertion IDs are single-use (`saml_replay_ids` table); a replayed assertion
  within its window is rejected.
- **Encrypted assertions** are not supported (rejected with a clear error) — send signed
  plaintext assertions over TLS.

## Single Logout

- SP-initiated: `GET /api/v1/saml/logout?name_id=…[&session_index=…]` → 302 to the IdP SLO.
- `GET /api/v1/saml/sls` accepts the IdP's LogoutResponse (bounces to the FE login page) or an
  IdP-initiated LogoutRequest (replies with a LogoutResponse).

## Security notes

- **Identity binding:** the SAML NameID is bound to the account on first login
  (`users.saml_subject`); a later change cannot silently take over another account.
- **Tenancy:** an email already in another org is rejected — SSO never moves a user between tenants.
- **Every SAML login/provision/logout writes an audit event** (`sso.saml.login` /
  `sso.saml.provisioned` / `sso.saml.logout`), visible at `GET /api/v1/audit`.

## Testing against a real IdP (Keycloak / Okta / Entra)

1. Create a SAML app; set the ACS + EntityID to the values `GET /api/v1/saml/config` reports;
   add a `groups` attribute mapper matching `group_role_map`; copy the IdP signing cert into
   `idp_x509_cert` and the SSO/SLO URLs + IdP EntityID.
2. `SAML_ENABLED=true`, restart, hit `/api/v1/saml/login?domain=<your-domain>`.

The automated suite (`tests/test_sso_saml.py`) signs assertions locally with a real RSA key
via `app/sso/xmldsig`, then drives the actual ACS — so signature (incl. tamper / wrong-cert /
wrapping), audience, recipient, time-window, InResponseTo, and single-use replay are all
covered without a live IdP.

## Why a local XML-DSig implementation (`app/sso/xmldsig.py`)

The project pins `cryptography<43` (sslyze 6.0). No `signxml` release fits that window without
either an incompatible `cryptography` or a `pyOpenSSL` whose `crypto.verify` was removed, and
`python3-saml` needs the native `xmlsec`/`libxmlsec1` toolchain (painful on Windows and in the
slim Docker image). `lxml` + `cryptography` — already dependencies — verify an enveloped
RSA/ECDSA-SHA-2 signature correctly, and keeping it in-tree lets us pin down XXE and XSW
explicitly (the two things a SAML verifier must not get wrong). Scope is deliberately narrow:
enveloped signatures, exclusive/inclusive C14N, SHA-256/384/512, RSA/ECDSA — everything else is
rejected, not accepted best-effort.
