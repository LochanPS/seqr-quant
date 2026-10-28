# pqcmap SDK — Release Checklist (v0.2.0)

Release readiness for the pqcmap SDK across all three languages. Prepared
2026-09-20. **Nothing here publishes anything** — publishing is gated on the
founder pushing a git tag (Python/Go) or running `npm publish` (JS). Stop at
"ready to tag."

- **Repo:** `github.com/LochanPS/SeQr-Labs` (monorepo; branch `main`)
- **Version:** `0.2.0` (all three languages)
- **Packages:** `pqcmap` (PyPI) · `@seqr/pqc` (npm) · `github.com/LochanPS/SeQr-Labs/pqcmap-go` (pkg.go.dev)

---

## 0. Status summary

| Language | Tests | Dry-run / build | Metadata | Verdict |
|---|---|---|---|---|
| Python (`pqcmap/`) | 160 pass, 1 skip (liboqs absent) | `python -m build` + `twine check` PASSED | pyproject, `py.typed`, LICENSE, CHANGELOG ✅ | **Ready to tag** |
| JS (`pqcmap-js/`, `@seqr/pqc`) | 42 pass (`node --test`) | `npm publish --dry-run` → **public access**, 20 files | package.json, `index.d.ts`, LICENSE, CHANGELOG ✅ | **Ready to publish** |
| Go (`pqcmap-go/`) | pass (`go test ./...`), `go vet` clean, `go mod verify` ok | `go build ./...` clean | go.mod path fixed, LICENSE, CHANGELOG ✅ | **Ready to tag** |

Local test matrix run this pass: **Python 3.11 / Node 22 / Go 1.27 on Windows.**
CI runs Python across Linux/macOS/Windows × 3.10–3.12 on tag push.

---

## 1. Fixes applied this pass (already committed to the tree — review before tagging)

All packages said `seqrlabs` but the real remote is `LochanPS/SeQr-Labs`. Corrected:

- **Version bump 0.1.0 → 0.2.0** — `pqcmap/pyproject.toml`, `pqcmap/pqcmap/__init__.py`,
  `pqcmap-js/package.json`, `pqcmap-js/index.js`. CHANGELOGs: `[Unreleased]` notes
  moved under `[0.2.0] - 2026-09-20`. (The old `0.1.0` = 2026-08-20 core-only stays as
  internal pre-release history; nothing was ever published publicly.)
- **Python metadata** — `Repository`/`Issues`/`Changelog` URLs → `LochanPS/SeQr-Labs`.
- **RELEASING.md** — PyPI trusted-publisher owner/repo → `LochanPS` / `SeQr-Labs`; tag example → `pqcmap-v0.2.0`.
- **JS** — added `publishConfig.access: public` (scoped `@seqr/pqc` is otherwise
  restricted and the first publish fails), repo url → `LochanPS/SeQr-Labs` (+`directory`),
  added **LICENSE** + **CHANGELOG.md** (were missing) to the package and `files`.
- **Go** — module path `github.com/seqrlabs/pqcmap-go` → **`github.com/LochanPS/SeQr-Labs/pqcmap-go`**
  (the old path never resolved — no such repo). Updated the two example imports + README.
  Added **LICENSE** + **CHANGELOG.md** (were missing).

Nothing else in the code changed. No functionality added.

---

## 2. Prerequisites — one-time, MUST be done before the first tag/publish

These are manual founder steps. Without them the publish jobs fail auth.

### Python (PyPI OIDC — no stored token)
1. On **PyPI** → *Your projects* → *Publishing* → add a **pending** trusted publisher:
   - Owner: `LochanPS` · Repo: `SeQr-Labs` · Workflow: `pqcmap.yml` · Environment: `pypi`
2. On **TestPyPI** → same, Environment: `testpypi`.
3. GitHub repo → *Settings* → *Environments* → create `pypi` and `testpypi`
   (optionally add required reviewers on `pypi` for a manual approval gate).

### JS (npm)
1. The **`@seqr` scope must exist** on npm and the publishing account must own it
   (create the `seqr` org on npmjs.com, or the scope, first). Otherwise
   `npm publish` 404s on the scope.
2. `npm login` locally, **or** set an automation `NPM_TOKEN` if you later add a workflow.

### Go
- No auth. pkg.go.dev indexes automatically once the tag is pushed and the module
  proxy fetches it (step 5 below primes it). Nothing to register.

---

## 3. Pre-tag verification (run locally — all currently PASS)

```bash
# Python
cd pqcmap && python -m pip install -e ".[dev]" && python -m pytest -q
python -m build && python -m twine check dist/*

# JS
cd ../pqcmap-js && npm test && npm publish --dry-run   # expect "public access"

# Go
cd ../pqcmap-go && go vet ./... && go test ./... && go mod verify
```

Also confirm the three versions still agree (`0.2.0`) and `git status` is clean.

---

## 4. Tag + publish commands (founder runs these — the actual release)

> Run from repo root on `main`, after step 1 is reviewed and step 2 is done.

### Python → PyPI (tag-gated workflow does the rest)
```bash
git tag -a pqcmap-v0.2.0 -m "pqcmap 0.2.0"
git push origin pqcmap-v0.2.0
```
The `pqcmap` workflow then runs `test → build → TestPyPI dry-run → PyPI` (OIDC).
The `pypi` job publishes only after the TestPyPI dry-run passes (and any environment
approval you configured). Nothing publishes without this `pqcmap-v*` tag.

### JS → npm (no workflow — manual publish)
```bash
cd pqcmap-js
npm publish            # publishConfig already forces --access public
```
(Optional: `npm publish --dry-run` one last time first.)

### Go → pkg.go.dev (tag with the subdir prefix — required for a module in a subdirectory)
```bash
git tag pqcmap-go/v0.2.0
git push origin pqcmap-go/v0.2.0
```

---

## 5. Post-publish verification

```bash
# Python
pip install pqcmap==0.2.0 && python -c "import pqcmap; print(pqcmap.__version__)"

# JS
npm view @seqr/pqc version

# Go — prime the proxy + pkg.go.dev index, then confirm
GOPROXY=proxy.golang.org go list -m github.com/LochanPS/SeQr-Labs/pqcmap-go@v0.2.0
# then browse: https://pkg.go.dev/github.com/LochanPS/SeQr-Labs/pqcmap-go@v0.2.0
```

---

## 6. Notes / residual items (non-blocking)

- **Repo name has capitals** (`SeQr-Labs`). Go module paths are case-sensitive; the
  proxy escapes uppercase (`!se!qr-!labs`) but resolution works. Kept as-is to match
  the actual repo. If you later create a `seqrlabs` org, all three packages' metadata
  must be re-pointed and Go's module path re-tagged (a breaking import change).
- **No JS/Go publish workflows** exist — only Python's `pqcmap.yml`. JS and Go release
  by the manual commands above. Adding `setup-node`/`setup-go` publish workflows later
  is optional hardening, not required for 0.2.0.
- **`go.mod` declares `go 1.24`**; local toolchain is 1.27. Compatible — left unchanged.
- **liboqs backend** is an optional extra (`pip install pqcmap[liboqs]`); the default
  pure-Python backend is what CI and these dry-runs exercised. The 1 skipped Python
  test is the real-liboqs path (absent locally and in default CI).
- Homepage/Docs URLs (`seqrlabs.com`, `docs.seqrlabs.com`) are website links, left
  unchanged — only repo-based URLs were corrected.
