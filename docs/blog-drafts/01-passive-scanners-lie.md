TITLE: Passive scanners say 0%. Active probing says 60%. Neither is the whole truth.
SLUG: passive-scanners-and-pqc
EXCERPT: Measuring 60+ Indian fintech endpoints, we found the standard way of checking post-quantum readiness is wrong — and the "good" number is a mirage.
TAGS: post-quantum, TLS, measurement, ML-KEM, CDN
STATUS: draft

---

If you ask a normal TLS scanner — sslyze, testssl, an SSL Labs run — whether a site
supports post-quantum cryptography, it will almost always say **0%**. We scanned 60+
Indian financial-services endpoints and confirmed it: passive scanning reports **zero**
hybrid post-quantum key exchange.

Then we scanned the same endpoints again, differently, and found **60%**.

## Why passive scanning misses PQC

A hybrid post-quantum key exchange (like `X25519MLKEM768`) is only negotiated if the
*client* offers an ML-KEM-capable ClientHello. A normal scanner uses a normal client — it
never offers one — so it never sees the server's PQC support. The capability is there; the
measurement misses it. Any "X% PQC" figure from passive external scanning is a lower bound
that can understate reality by tens of points.

To measure it accurately you have to **actively probe**: send an ML-KEM-capable ClientHello
(OpenSSL 3.5+ ships the standardized groups) and read the group the server actually
negotiates. That's the difference between "we think you have no PQC" and the truth.

## The catch: the 60% is a mirage

Here's the part that matters. That 60% is almost entirely a **CDN default**. Endpoints
behind Amazon CloudFront and Cloudflare inherit hybrid PQC because those providers turned
it on. Directly-hosted origins? **0%.** And across the board:

- **100% of certificates are still classical** (RSA/ECDSA) — quantum-forgeable.
- Roughly **half of organisations expose a non-CDN origin** endpoint that sits *outside*
  the protected edge — so the edge PQC is bypassable.

Nobody in the data deliberately migrated. They inherited a partial, edge-only protection
and would be measured as either "nothing" (passive) or "mostly safe" (a CDN dashboard),
while being **end-to-end quantum-vulnerable with no cryptographic inventory.**

## What to actually do

1. **Measure with an active probe** — passive numbers are not trustworthy for PQC.
2. **Don't mistake edge PQC for quantum-safety.** It protects one hop. Your certificates,
   your origin servers, and any exposed origin are still classical.
3. **Build a cryptographic inventory (a CBOM).** It's the first thing PCI DSS 12.3.3 and
   SEBI's CSCRF ask for — and the one almost nobody has.

We built SeQr to do exactly this: measure what passive tools miss, and turn it into an
audit-ready inventory in minutes. The free CLI (`pip install seqr`) does passive
web/SSH/mail scanning; the platform adds the active PQC probe, origin discovery, the CBOM,
and compliance mapping.

*Full measurement study + datasets: github.com/LochanPS/seqr-labs-research*
