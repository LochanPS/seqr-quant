# Disclosure notice — email template

Fill the [BRACKETS] per entity. Keep it factual, non-alarmist, and entity-specific.
Never reference another company's findings.

---

**Subject:** Security notice — exposed origin endpoint(s) for [DOMAIN]

Hello [SECURITY TEAM / NAME],

I'm P S Lochan, an independent security researcher (SeQr Labs). While measuring
post-quantum TLS posture across Indian financial-services infrastructure, I identified,
via **passive DNS only**, that the following endpoint(s) associated with **[DOMAIN]**
resolve to non-CDN public IP addresses — i.e. they appear to be reachable directly,
outside your CDN edge:

- `[api.domain.com]` → `[public IP]`
- `[sftp.domain.com]` → `[public IP]`

Why this may matter: when a site is fronted by a CDN (which provides TLS termination,
WAF, and — increasingly — hybrid post-quantum key exchange), a directly-reachable origin
lets a client bypass those protections and connect to the origin server directly. I did
**not** connect to, scan, or test these origins — this is purely a DNS-resolution
observation of public records. I'm sharing it so your team can verify whether these
endpoints are intended to be publicly reachable.

I plan to publish **aggregate** research on origin exposure across the sector (no entity
named). I will not publish anything identifying [DOMAIN] before **[DATE — 45+ days out]**,
and would welcome confirmation once this is reviewed or addressed.

Happy to share more detail or coordinate through CERT-In if you prefer. No response is
required, but I'm glad to help.

Best regards,
P S Lochan
SeQr Labs · contact@seqrlabs.com
[optional: research repo link]

---

**Do:** be specific, factual, give a date, offer to help.
**Don't:** imply breach, exaggerate severity, name other companies, or attach the full dataset.
