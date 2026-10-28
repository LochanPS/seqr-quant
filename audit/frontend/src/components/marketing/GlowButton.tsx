"use client";

import { useState } from "react";
import { marketing } from "@/lib/marketing-tokens";

type GlowButtonProps = {
  children: React.ReactNode;
  href?: string;
  onClick?: () => void;
  variant?: "primary" | "secondary";
  className?: string;
};

export function GlowButton({ children, href, onClick, variant = "primary", className }: GlowButtonProps) {
  const [hover, setHover] = useState(false);

  const style =
    variant === "primary"
      ? {
          background: marketing.accent,
          color: "#000",
          border: "1px solid transparent",
          boxShadow: hover ? `0 0 20px ${marketing.accentGlow}, 0 0 40px rgba(166,90,22,0.15)` : "none",
        }
      : {
          background: "transparent",
          color: marketing.textMuted,
          border: `1px solid ${hover ? "rgba(166,90,22,0.4)" : marketing.border}`,
          boxShadow: hover ? "0 0 24px rgba(166,90,22,0.08)" : "none",
        };

  const sharedClassName = `inline-flex items-center justify-center rounded-lg px-6 py-3 text-sm font-semibold transition-all ${className ?? ""}`;

  if (href) {
    return (
      <a
        href={href}
        className={sharedClassName}
        style={style}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
      >
        {children}
      </a>
    );
  }

  return (
    <button
      onClick={onClick}
      className={sharedClassName}
      style={style}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      {children}
    </button>
  );
}
