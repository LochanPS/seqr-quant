# DESIGN.md — SeQr

Aesthetic lane: **measurement instrument meets modern deeptech.** Amber signal on warm
near-black, the polish of Linear/Vercel, the soul of an oscilloscope/spectrum analyzer.
Terminal accents are seasoning, not the whole meal. Reference drench: "amber-on-black
instrument readout with Vercel-grade motion." Avoid the crypto-neon and fintech-navy reflexes.

## Color (OKLCH; never pure #000/#fff)
Strategy: **Committed** — amber is load-bearing identity, spread on a warm near-black.

- `--bg`         oklch(0.15 0.006 72)   near-black, faint warm tint (not #000)
- `--bg-raise`   oklch(0.19 0.008 72)   raised surface
- `--ink`        oklch(0.92 0.015 82)   cream primary text (was #EDE7DC)
- `--ink-muted`  oklch(0.92 0.015 82 / 0.60)
- `--ink-faint`  oklch(0.92 0.015 82 / 0.36)
- `--amber`      oklch(0.76 0.13 74)    the signal / accent (was #D7A352)
- `--amber-deep` oklch(0.62 0.14 66)    pressed / gradient stop
- `--line`       oklch(0.92 0.015 82 / 0.10)
- Scan semantics (ONLY inside scan-result surfaces, never brand chrome):
  safe emerald oklch(0.72 0.15 162), vulnerable rose oklch(0.65 0.2 18),
  planned violet oklch(0.62 0.16 300).

Existing `lib/marketing-tokens.ts` hex values map to the above; keep the token names, deepen
the values toward these. `#000` background becomes the warm near-black.

## Typography
Two families, strong weight/scale contrast. (Both Google Fonts, via next/font.)
- **Display + body: Bricolage Grotesque** — contemporary grotesque with character; not on the
  reflex-reject list. Hero uses weight 700-800, tight tracking, fluid clamp().
- **Mono: JetBrains Mono** — the instrument voice: terminal, measured data, field labels,
  algorithm names (X25519MLKEM768, RSA-2048). Uppercase micro-labels with letter-spacing.
- Scale: fluid `clamp()`, ratio >= 1.25. Hero display can go very large (clamp up to ~7rem).
- Dark-bg line-height: +0.05-0.1.

## Motion
- Ease-out-expo / quart only. No bounce, no elastic. Never animate layout props.
- One orchestrated page-load (staggered hero reveal) + scroll-triggered section reveals
  (framer-motion whileInView). Signature moments are scroll-scrubbed, not autoplay loops.
- Background: a performant canvas/WebGL "signal field" (drifting particles / scan sweep),
  low opacity, amber. NOT a lattice. Respect prefers-reduced-motion.

## Signature moments (the three the hero earns)
1. **Mirage reveal** — scroll-scrubbed: "0%" (passive) morphs/counts to "60%" (active), then
   the twist stats resolve (100% classical certs, ~half expose an origin). Bars fill on scroll.
2. **Live scan terminal** — upgraded typed scan output with a scan-sweep line + glow; real
   result fields (TLS 1.3, X25519MLKEM768 [HYBRID], edge/origin).
3. **Edge vs origin** — 2D SVG/canvas diagram: client -> CDN edge (amber, hybrid) vs the
   exposed origin (dim, classical) it routes around. Animated packet along both paths.

## Layout
- Left-aligned, asymmetric compositions over centered stacks. Break the grid for the hero
  word. Fluid `clamp()` spacing; vary rhythm (generous section gaps, tight data groupings).
- Cards only where they are the right affordance (pricing, result panels). No icon-title-text
  card grids. No nested cards.
- Section-level art direction: each signature moment can own its visual world.

## Bans (project-specific, on top of skill bans)
- No lattice / wireframe globe / matrix rain / hexagon-circuit background.
- No gradient-clip text. Emphasis via weight/size/amber fill.
- No side-stripe accent borders (there were some `borderLeft` accents — replace).
- No em dashes in copy.
