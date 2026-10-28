# @seqr/pqc examples

Runnable, self-contained demos. No external services required.

| Example | What |
|---|---|
| [`auth_demo.js`](auth_demo.js) | ML-DSA JWT auth: LocalKeyStore holds the key, login mints a token, a route verifies it. |
| [`tls_report.js`](tls_report.js) | Honest PQC-hybrid TLS capability report for this Node runtime. |

```bash
node examples/auth_demo.js
node examples/tls_report.js
```
