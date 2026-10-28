# Responsible disclosure — origin-exposure findings

**Private. Do not publish.** This governs notifying the entities whose exposed origins are
recorded in `origin_leakage_results.json` (withheld from the public repo until this completes).

## What we found (per entity)
During the PQC measurement study, passive DNS resolution of common origin-leak subdomains
(`api.`, `dev.`, `sftp.`, `origin.`, `mail.`, …) surfaced hostnames resolving to **non-CDN
public IPs** — i.e. an origin endpoint reachable **outside** the CDN's protected edge. This is
a configuration exposure, **not a breach and not an exploited vulnerability**:
- The CDN's protections (WAF, DDoS, and — relevant to this paper — hybrid-PQC key exchange at
  the edge) can be bypassed by connecting to the origin IP directly.
- No origin we discovered served a PQC certificate; origins are classical.
- We did **not** scan, connect to, exploit, or access any origin — only passive DNS was used.

## Why disclose
The paper reports only the **aggregate** statistic (51% of the corpus exposes an origin) and
**names no entity**. But the underlying dataset identifies endpoints, so we notify affected
entities *before* any dataset release, per coordinated-disclosure norms.

## Process + timeline
1. **Notify** each affected entity's security contact (security@ / responsible-disclosure page
   / CERT-In-listed contact). Send the email below; attach the entity's specific findings.
2. **Grace period: 45 days** from first contact for them to remediate or respond.
3. **Publish** the raw dataset only after 45 days AND after material exposures are addressed or
   acknowledged. The aggregate paper can publish immediately (no entity named).
4. Log each notification (date sent, contact, response) in a private tracker.

## Finding a contact (no personal-data scraping)
Use the entity's **security.txt** (`https://<domain>/.well-known/security.txt`), their
responsible-disclosure/bug-bounty page, `security@<domain>`, or their CERT-In-listed contact.
Do not scrape personal emails.

---

## Email template (personalise the [bracketed] parts)

> **Subject:** Coordinated disclosure — [company] origin endpoint reachable outside your CDN
>
> Hello [company] security team,
>
> I'm P S Lochan, an independent security researcher (SeQr Labs). During a measurement study of
> post-quantum cryptography adoption across Indian financial-services endpoints, I observed —
> using only public DNS — that the following hostname(s) associated with [company] resolve to a
> public IP **outside your CDN**:
>
>     [hostname] → [IP]   (e.g. api.example.com → 203.0.113.10, direct AWS)
>
> This means a client can reach your origin directly, bypassing the CDN edge that provides your
> WAF/DDoS protection and (increasingly) hybrid post-quantum TLS. The directly-reachable origin
> uses classical cryptography. **I did not connect to, scan, or access the origin — this is
> passive DNS observation only, and I am not reporting any breach.**
>
> Suggested mitigations: restrict the origin to accept traffic only from your CDN (origin
> allowlisting / authenticated origin pulls / mTLS), or place the endpoint behind the CDN.
>
> My research reports only an aggregate statistic and **names no organisation**. I am sharing
> your specific finding privately so you can address it. I plan to keep the identifying details
> private for at least **45 days** and will not publish anything that identifies [company]
> without coordinating with you first.
>
> Happy to share more detail or verify a fix. You can reach me at contact@seqrlabs.com.
>
> Regards,
> P S Lochan · SeQr Labs · ORCID 0009-0006-1623-2684

---

**Note:** These notices are courtesy coordinated disclosures of a configuration observation, not
vulnerability reports under any bounty program. Keep the tone factual and non-alarmist. If an
entity asks you to stop contacting them, comply.
