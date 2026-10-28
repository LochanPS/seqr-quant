# arXiv submission — step by step

**File:** `PQC_India_Measurement.tex` (self-contained, compiles with `tectonic` or
`pdflatex`; verified to build to a ~63 KB PDF).

## Before you submit
1. **Disclosure note.** The paper reports only aggregates (no entity named), so it is safe
   to post. The *raw origin-exposure dataset* stays withheld (it names endpoints) — already
   the case; nothing to do.
2. **Finalise the author block.** Currently `Lochan Pokkali / SeQr Labs / contact@seqrlabs.com`.
   arXiv allows an independent affiliation — fine as is.

## Get an arXiv account that can submit
- arXiv requires either an existing account with submit rights or **endorsement** for
  `cs.CR` (first-time submitters in a category often need one endorser who has published
  there). Register at arxiv.org → if prompted for endorsement, ask one academic contact in
  security/crypto to endorse (one click for them).

## Submit
1. arxiv.org → **Submit** → primary category **cs.CR** (Cryptography and Security),
   cross-list **cs.NI** (Networking).
2. Upload **`PQC_India_Measurement.tex`** as the source. arXiv compiles it server-side
   (TeX Live). No need to upload the PDF — but you can upload the built PDF as a check.
3. Title / abstract: paste from the paper (arXiv asks for plain-text abstract separately).
4. License: **CC BY 4.0** (recommended for max reach) or arXiv non-exclusive.
5. Submit → it enters the next mailing (usually same-day to next business day) → you get
   `arXiv:26xx.xxxxx`.

## After it's live
- Drop the `arxiv.org/abs/...` link into LinkedIn/X posts and the cold-outreach opener.
- Update the public repo README + the white paper to cite the arXiv ID.

## Optional: also submit to a venue
INDOCRYPT 2026 (Indian crypto conference) is a natural fit. arXiv preprint + venue
submission are compatible (arXiv is a preprint server, not a publication).

## Rebuild the PDF locally
```
tectonic PQC_India_Measurement.tex
```
(One cosmetic "overfull hbox" warning — ignore; it's a single slightly-wide line.)
