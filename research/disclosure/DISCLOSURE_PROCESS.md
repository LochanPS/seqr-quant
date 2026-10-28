# Responsible disclosure — origin-exposure dataset

**Status: required before publishing `origin_leakage_results.json` or naming any entity.**

The paper (`research/paper/PQC_India_Measurement.md`) is **aggregate only** — no entity is
named in any weakness claim — so it is already safe to publish. What is **not** yet publishable
is the raw origin-exposure dataset (`research/origin_leakage_results.json`), which lists
per-entity exposed origin endpoints. Before that dataset is released, or before any entity is
named publicly, each affected organisation must be notified and given time to remediate.

## What was found (per entity)
For each affected domain, `origin_leakage_results.json` records origin endpoints (e.g.
`api.`, `dev.`, `sftp.` subdomains) that resolve to non-CDN public IPs — i.e. reachable
outside the protected CDN edge. This was found via **passive DNS only**; no origin was
scanned or exploited. It is an *exposure* finding, not a confirmed vulnerability.

## Process (coordinated disclosure)
1. **Compile the list.** From `origin_leakage_results.json`, list affected entities + their
   exposed origin hostnames. Keep this private.
2. **Find a security contact**, in this order:
   - `https://<domain>/.well-known/security.txt`
   - `security@<domain>` / `soc@` / `infosec@`
   - CISO / Head of Information Security via LinkedIn (warm intro if possible)
   - For the financial sector, you may also coordinate through **CERT-In**
     (incident@cert-in.org.in) as India's national CERT.
3. **Send the notice** (see `notice_template.md`). One per entity. Findings specific to that
   entity only — never mention another company.
4. **Give a remediation window** — 45 days is reasonable for an exposure (not an active
   exploit); extend to 90 if they engage.
5. **Track responses** in `disclosure_log.md` (create locally; keep private): date sent,
   contact, acknowledged, remediated.
6. **Publish** only after: (a) the window elapses, and (b) ideally the origin is remediated or
   the entity consents. Even then, prefer publishing **redacted/aggregate** unless there is a
   clear public-interest reason to name.

## Notes
- This is a good-faith courtesy + reduces legal/PR risk; it is not a legal obligation for a
  passive DNS observation of public records, but it is the professional norm.
- Do **not** rescan or probe the origins as part of disclosure — the finding stands on the
  passive data already collected.
- The offer of a free SeQr scan can be a natural, non-pushy follow-up once they engage — but
  lead with the disclosure, not the sales pitch.
