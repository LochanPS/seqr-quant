import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRelative(date: string | Date | null | undefined): string {
  if (!date) return "—";
  const d = typeof date === "string" ? new Date(date) : date;
  const diff = Date.now() - d.getTime();
  const sec = Math.round(diff / 1000);
  if (sec < 60) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 30) return `${day}d ago`;
  return d.toLocaleDateString();
}

export function formatDate(date: string | Date | null | undefined): string {
  if (!date) return "—";
  const d = typeof date === "string" ? new Date(date) : date;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncateMiddle(str: string, max = 48): string {
  if (str.length <= max) return str;
  const half = Math.floor((max - 1) / 2);
  return `${str.slice(0, half)}…${str.slice(str.length - half)}`;
}

// Crypto-agility score is 0–10, but the ceiling for a well-configured *classical* stack is
// ~6.5 (full PQC readiness is not yet deployable), so a bare "6.5/10" misreads as a failure.
// These tiers reframe the number by what's actually achievable today.
export function agilityTier(score: number | null | undefined): {
  label: string;
  variant: "vulnerable" | "planned" | "safe";
} {
  const s = score ?? 0;
  if (s < 3) return { label: "Legacy", variant: "vulnerable" };
  if (s < 5.5) return { label: "Classical", variant: "planned" };
  if (s < 7.5) return { label: "Transition-ready", variant: "planned" };
  if (s < 9) return { label: "Hybrid-adopted", variant: "safe" };
  return { label: "PQC-ready", variant: "safe" };
}
