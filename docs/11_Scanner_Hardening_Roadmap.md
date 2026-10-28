# Scanner Hardening Roadmap — accuracy / scale / reliability

Concrete next improvements for the SeQr scanner, prioritized. Reflects the current state
(post active-PQC probe, origin discovery, multi-protocol). Source of truth for task #16.
Legend: **P0** = do before first paying customer · **P1** = soon after · **P2** = later.

---

## Accuracy (findings must be defensible)

- **P0 — Origin assessment (Phase 2, task #22).** Actively TLS-scan discovered origin
  candidates for a customer's own assets → measure end-to-end posture (edge hybrid vs origin
  classical), not just the edge. The single biggest accuracy + differentiation win.
- **P0 — CDN-detection confidence.** Current detection (reverse-DNS + published CIDR +
  headers) can false-positive (e.g. a shared cloud IP read as a CDN). Add ASN lookup, refresh
  CIDR ranges, and attach a `cdn_confidence` so the UI/PDF can hedge low-confidence calls.
- **P1 — Certificate chain, not just leaf.** Today only the leaf cert is classified. Add
  intermediate/root inspection, chain validity, expiry-window flags, and (future) PQC-signature
  detection (ML-DSA) across the chain.
- **P1 — Key size + symmetric surfacing.** Store `key_size` explicitly (RSA-2048 vs 4096 differ
  in migration target) and surface symmetric strength (AES-128 → Grover-weakened → prefer 256).
- **P1 — Active probe breadth.** Offer all standardized hybrid groups (X25519MLKEM768,
  SecP256r1MLKEM768, SecP384r1MLKEM1024) and record which negotiated; handle STARTTLS variants
  for smtp/imap/pop3/postgres in the active probe.
- **P2 — Agility-score calibration.** Today's best practice caps ~5.5/10 and reads as "fail".
  Add tier labels (e.g. 0–3 Legacy, 4–6 Modern-classical, 7–8 Transition-ready, 9–10 PQC-ready)
  and disclose the scoring rubric. (See deferred-polish item.)

## Scale (large inventories, continuous monitoring)

- ✅ **P0 — Async worker in production (A6, done).** Dedicated Celery worker in
  `deploy/worker/` (own Dockerfile + `docker-compose.yml`, backend+worker+redis+db,
  `CELERY_ALWAYS_EAGER=false`). `/assets/{id}/scan` enqueues + returns a job id
  immediately; the worker streams live WS progress (step + per-finding events on
  `scan:{id}`). Per-org fairness cap (`MAX_CONCURRENT_SCANS_PER_ORG`) + global
  `--concurrency`; `prefetch=1` + `acks_late`. Batch scan: `POST /assets/scan-all`.
  Load test: `deploy/worker/loadtest.py` (~100 assets). WS org-boundary preserved.
- **P1 — Bounded concurrency.** `scan_domains` is sequential + rate-limited (0.5 s). Add a
  bounded thread/async pool (e.g. 8 concurrent) with per-host politeness for large asset sets.
  (Cross-asset concurrency now handled by the worker pool + per-org cap; this item is the
  intra-scan `scan_domains` loop.)
- **P1 — Scheduled / continuous scans.** Cron-triggered re-scans per asset + scan diffing
  (what changed since last scan) — the "continuous monitoring" the marketing promises.
- **P2 — Incremental / caching.** Skip endpoints unchanged since last scan (cert serial + IP)
  to cut cost on large inventories.

## Reliability (never crash, always honest)

- **P0 — Error taxonomy + partial results.** Distinguish DNS-fail / conn-refused / WAF-block /
  timeout / TLS-error (partly via `scan_outcome`); always return a labeled result rather than a
  hard failure. Surface the reason in the UI.
- **P1 — Timeouts + retry/backoff.** Aggressive-WAF and slow hosts: tune per-phase timeouts,
  add one bounded retry with backoff; keep the hard overall cap.
- **P1 — OpenSSL 3.5 dependency management.** Active probe needs OpenSSL ≥3.5; the deploy image
  (trixie) has it, but detect + fall back to passive with a clear note when absent (already
  fail-safe — make the note visible).
- **P2 — Observability.** Structured scan logs + basic metrics (durations, outcomes, probe
  success rate) for debugging customer scans at scale.
- **P2 — IPv6 scanning.** Validate + scan AAAA endpoints (SSRF guard already enumerates v6).

## Coverage (breadth — after the above)

- ✅ **P1 — More TLS-bearing services (A7, done):** MongoDB, AMQP (RabbitMQ), gRPC over TLS.
  All three speak TLS directly on connect (no STARTTLS), so they reuse the existing direct-TLS
  analysis + active PQC probe — only the default port differs (`_DIRECT_TLS_PROTOCOLS`:
  mongodb 27017, amqp 5671, grpc 443 + ALPN h2). Asset types wired end-to-end
  (`assets._ASSET_TYPES`, `scan_tasks._TLS_PROTOCOLS`, `AddAssetDialog.tsx`). Live-verified:
  grpcb.in (TLS 1.3, RSA-2048, X25519) + local self-signed servers on 27017/5671.
  (MySQL still deferred — its TLS is a mid-handshake upgrade sslyze cannot drive.)
- **P2 — VPN/IPsec, S/MIME, code-signing certs** for a fuller CBOM.
- **P2 — Code-scan depth:** more languages + hardcoded-key/secret detection alongside the
  existing 30 crypto-API patterns.

---

## Sequencing note
Do the **P0** accuracy/reliability items with the first real customer scans (origin assessment,
CDN confidence, error taxonomy, async worker). P1/P2 follow revenue. Each item should ship with
tests, and any customer-facing claim must stay evidence-based (measured, not inferred).
