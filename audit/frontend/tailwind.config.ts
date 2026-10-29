import type { Config } from "tailwindcss";

// Every color is a CSS variable holding RGB channels (see globals.css), so one token set
// drives both the paper (light) and carbon (dark) themes and alpha modifiers still work.
const tone = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

const config: Config = {
  darkMode: ["selector", '[data-theme="dark"]'],
  content: ["./src/**/*.{ts,tsx,mdx}"],
  theme: {
    // Radius is zero across the system; `xs` exists only for anti-aliasing tiny chips.
    borderRadius: {
      none: "0",
      xs: "2px",
      full: "9999px",
    },
    boxShadow: {
      none: "none",
    },
    extend: {
      colors: {
        bg: tone("bg"),
        surface: tone("surface"),
        "surface-2": tone("surface-2"),
        ink: tone("ink"),
        "ink-2": tone("ink-2"),
        "ink-3": tone("ink-3"),
        rule: tone("rule"),
        accent: tone("accent"),
        immediate: tone("immediate"),
        urgent: tone("urgent"),
        planned: tone("planned"),
        safe: tone("safe"),
        hybrid: tone("hybrid"),
      },
      fontFamily: {
        display: ["var(--font-display)", "ui-serif", "Georgia", "serif"],
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      fontSize: {
        eyebrow: ["11px", { lineHeight: "16px", letterSpacing: "0.08em" }],
      },
      transitionTimingFunction: {
        instrument: "cubic-bezier(0.2, 0, 0, 1)",
        press: "cubic-bezier(0.34, 1.4, 0.64, 1)",
      },
      transitionDuration: {
        micro: "120ms",
        ui: "240ms",
      },
      maxWidth: {
        measure: "68ch",
        page: "1320px",
      },
      keyframes: {
        "skeleton-breathe": {
          "0%, 100%": { opacity: "0.55" },
          "50%": { opacity: "1" },
        },
        "rule-shrink": {
          from: { transform: "scaleX(1)" },
          to: { transform: "scaleX(0)" },
        },
      },
      animation: {
        skeleton: "skeleton-breathe 1.6s cubic-bezier(0.2, 0, 0, 1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;
