export const tokens = {
  // Brand colors — unified with the landing page (marketing-tokens.ts)
  quantum: "#A65A16", // SeQr burnt amber — brand accent (was #D7A352)
  safe: "#10b981", // emerald — secure
  vulnerable: "#f43f5e", // rose — quantum exposed
  urgent: "#f59e0b", // amber — HNDL / urgent
  planned: "#8b5cf6", // violet — planned migration

  // Dark mode surfaces — parchment-on-true-black, matches marketing
  dark: {
    bg: "#000000", // page background — true black
    surface: "#131110", // card background — warm, lifted off black
    elevated: "#1e1c19", // hover / elevated
    border: "#1a1917", // dividers — parchment @ ~0.10
    muted: "#8a857c", // secondary text
  },

  // Light mode surfaces
  light: {
    bg: "#f8fafc", // slate-50
    surface: "#ffffff",
    elevated: "#f1f5f9", // slate-100
    border: "#e2e8f0", // slate-200
    muted: "#94a3b8", // slate-400
  },
} as const;

/** Map a 0–100 risk score to a brand color. */
export function riskColor(score: number): string {
  if (score <= 30) return tokens.safe;
  if (score <= 60) return tokens.urgent;
  return tokens.vulnerable;
}

/** Map a risk label to a brand color. */
export function riskLabelColor(label: string): string {
  switch (label?.toLowerCase()) {
    case "low":
      return tokens.safe;
    case "medium":
      return tokens.urgent;
    case "high":
      return tokens.vulnerable;
    case "critical":
      return tokens.vulnerable;
    default:
      return tokens.quantum;
  }
}

export const timelineColor: Record<string, string> = {
  IMMEDIATE: tokens.vulnerable,
  URGENT: tokens.urgent,
  PLANNED: tokens.planned,
  ROADMAP: tokens.quantum,
};

export const quantumStatusColor: Record<string, string> = {
  vulnerable: tokens.vulnerable,
  safe: tokens.safe,
  hybrid: tokens.planned,
};
