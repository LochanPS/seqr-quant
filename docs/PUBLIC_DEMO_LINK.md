# Public demo link (no AWS, no account, no card)

AWS is blocked on the available account (an org policy denies EC2/S3/etc, and only the
organization owner can lift it). This gives judges a public `https://…` link to the running
product instead, straight from the laptop, via a free Cloudflare quick tunnel.

## Run it (three terminals, in order)
```bat
scripts\run-local-backend.cmd
```
```bat
scripts\run-public-frontend.cmd
```
```bat
scripts\run-public-tunnel.cmd
```
The third window prints a line like:

```
https://licensing-genre-bugs-request.trycloudflare.com
```

Share that URL. Sign in with `demo@seqrlabs.com` / `demodemo123`. The whole dashboard works
over it — posture, context-aware risk, the QpiAI remediation planner, CBOM, attestation.

## How it works (why it's one clean link)
- `run-public-frontend.cmd` sets `NEXT_PUBLIC_API_URL=/api/v1` (a **relative** path).
- The browser therefore calls `https://<tunnel>/api/v1/...`, same origin as the page.
- Next.js rewrites `/api/*` to `http://localhost:8000` **server-side** (see `next.config.mjs`),
  so there is no CORS and the backend is never exposed directly — only the dashboard is.
- The tunnel points only at port 3000 (the frontend).

## Notes
- **The URL changes every run.** Start `run-public-tunnel.cmd` right before you present and
  keep the window open. Closing it ends the link.
- Live scan progress (WebSocket) is the one thing that won't stream over the quick tunnel; the
  core demo paths don't need it.
- `cloudflared.exe` lives in the git-ignored `.local/`; the tunnel script re-downloads it if
  missing.
- This is a demo link to seeded data. Don't leave it running long-term.

## A stable URL on seqrlabs.com (later)
Needs either AWS unblocked (org owner lifts the SCP), or the domain moved onto a free
Cloudflare account with a *named* tunnel. Not required for the hackathon.
