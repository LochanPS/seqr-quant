export const marketing = {
  // brand palette
  bg: '#000000',
  textPrimary: '#EDE7DC',
  textMuted: 'rgba(237, 231, 220, 0.62)',
  textFaint: 'rgba(237, 231, 220, 0.38)',
  surface: 'rgba(237, 231, 220, 0.04)',
  border: 'rgba(237, 231, 220, 0.10)',
  borderStrong: 'rgba(237, 231, 220, 0.18)',
  accent: '#A65A16',
  accentSoft: 'rgba(166, 90, 22, 0.14)',
  accentGlow: 'rgba(166, 90, 22, 0.35)',
  // semantic scan-result colors — do not use for brand
  safe: '#10b981',
  vulnerable: '#f43f5e',
  urgent: '#f59e0b',
  planned: '#8b5cf6',
} as const;

// Act I / close — light "paper" palette (editorial, institutional). Warm off-white,
// near-black ink, a DEEPER amber (the #D7A352 has poor contrast on white).
export const paper = {
  bg: '#F4F1E9',
  bgRaise: '#FBF9F4',
  ink: '#171512',
  inkMuted: 'rgba(23, 21, 18, 0.64)',
  inkFaint: 'rgba(23, 21, 18, 0.42)',
  line: 'rgba(23, 21, 18, 0.12)',
  lineStrong: 'rgba(23, 21, 18, 0.22)',
  accent: '#A65A16',
  accentInk: '#7A410F',
  accentSoft: 'rgba(166, 90, 22, 0.09)',
  // dark instrument panel that can sit inside a light section
  panel: '#141210',
  panelInk: '#EDE7DC',
} as const;
