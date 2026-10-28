"use client";

import { useEffect, useRef, useState } from "react";
import { marketing } from "@/lib/marketing-tokens";

const SCENARIOS = [
  {
    domain: "api.examplebank.in",
    lines: [
      { text: "Scanning api.examplebank.in...", delay: 0 },
      { text: "", delay: 400 },
      { text: "api.examplebank.in:443", delay: 600 },
      { text: "─────────────────────────────────────", delay: 700 },
      { text: "TLS Version:    TLS_1_3", delay: 900 },
      { text: "Certificate:    RSA-2048        [QUANTUM-VULNERABLE]", delay: 1100, highlight: "QUANTUM-VULNERABLE" },
      { text: "Key Exchange:   X25519          [QUANTUM-VULNERABLE]", delay: 1300, highlight: "QUANTUM-VULNERABLE" },
      { text: "Deployment:     Level 1 / 4 — Modern Classical", delay: 1500 },
      { text: "", delay: 1700 },
      { text: "PQC Status: MIGRATION REQUIRED (not a current threat)", delay: 1900, highlight: "MIGRATION REQUIRED" },
      { text: "", delay: 2100 },
      { text: "✓ Scan complete in 2.1s", delay: 2300, highlight: "✓" },
    ],
  },
  {
    domain: "payments.finco.in",
    lines: [
      { text: "Scanning payments.finco.in...", delay: 0 },
      { text: "", delay: 400 },
      { text: "payments.finco.in:443", delay: 600 },
      { text: "─────────────────────────────────────", delay: 700 },
      { text: "TLS Version:    TLS_1_2         [PLANNED]", delay: 900, highlight: "PLANNED" },
      { text: "Certificate:    ECDSA-P256-256  [QUANTUM-VULNERABLE]", delay: 1100, highlight: "QUANTUM-VULNERABLE" },
      { text: "Key Exchange:   ECDH            [QUANTUM-VULNERABLE]", delay: 1300, highlight: "QUANTUM-VULNERABLE" },
      { text: "Deployment:     Level 1 / 4 — Modern Classical", delay: 1500 },
      { text: "CDN:            Cloudflare (low migration effort)", delay: 1700 },
      { text: "", delay: 1900 },
      { text: "PQC Status: MIGRATION REQUIRED (not a current threat)", delay: 2100, highlight: "MIGRATION REQUIRED" },
      { text: "", delay: 2300 },
      { text: "✓ Scan complete in 1.8s", delay: 2500, highlight: "✓" },
    ],
  },
  {
    domain: "auth.healthtech.in",
    lines: [
      { text: "Scanning auth.healthtech.in...", delay: 0 },
      { text: "", delay: 400 },
      { text: "auth.healthtech.in:443", delay: 600 },
      { text: "─────────────────────────────────────", delay: 700 },
      { text: "TLS Version:    TLS_1_3", delay: 900 },
      { text: "Certificate:    RSA-4096        [QUANTUM-VULNERABLE]", delay: 1100, highlight: "QUANTUM-VULNERABLE" },
      { text: "Key Exchange:   X25519          [QUANTUM-VULNERABLE]", delay: 1300, highlight: "QUANTUM-VULNERABLE" },
      { text: "Deployment:     Level 1 / 4 — Modern Classical", delay: 1500 },
      { text: "HNDL Risk:      HIGH (auth endpoint, long-lived sessions)", delay: 1700, highlight: "HIGH" },
      { text: "", delay: 1900 },
      { text: "PQC Status: MIGRATION REQUIRED (HNDL exposure elevated)", delay: 2100, highlight: "MIGRATION REQUIRED" },
      { text: "", delay: 2300 },
      { text: "✓ Scan complete in 3.2s", delay: 2500, highlight: "✓" },
    ],
  },
];

const PROMPT = "$ seqr scan domain ";
const TYPING_SPEED = 55;
const PAUSE_AFTER = 2800;

function colorLine(text: string, highlight?: string): React.ReactNode {
  if (!highlight || !text.includes(highlight)) {
    if (text.startsWith("─")) return <span style={{ color: marketing.textFaint }}>{text}</span>;
    if (text.startsWith("✓")) return <span style={{ color: marketing.safe }}>{text}</span>;
    if (text.startsWith("TLS") || text.startsWith("Cert") || text.startsWith("Key") || text.startsWith("Dep") || text.startsWith("CDN") || text.startsWith("HNDL"))
      return (
        <span>
          <span style={{ color: marketing.textMuted }}>{text.slice(0, 16)}</span>
          <span style={{ color: marketing.textPrimary }}>{text.slice(16)}</span>
        </span>
      );
    if (text.startsWith("PQC Status")) {
      return <span style={{ color: marketing.urgent }}>{text}</span>;
    }
    return <span style={{ color: marketing.textPrimary }}>{text}</span>;
  }

  const idx = text.indexOf(highlight);
  const color = highlight === "QUANTUM-VULNERABLE" ? marketing.vulnerable
    : highlight === "PLANNED" ? marketing.planned
    : highlight === "HIGH" ? marketing.urgent
    : highlight === "MIGRATION REQUIRED" ? marketing.urgent
    : marketing.safe;

  return (
    <span>
      <span style={{ color: marketing.textMuted }}>{text.slice(0, idx)}</span>
      <span style={{ color, fontWeight: 700 }}>{highlight}</span>
      <span style={{ color: marketing.textMuted }}>{text.slice(idx + highlight.length)}</span>
    </span>
  );
}

export function TerminalAnimation() {
  const [scenarioIdx, setScenarioIdx] = useState(0);
  const [typed, setTyped] = useState("");
  const [visibleLines, setVisibleLines] = useState<number[]>([]);
  const [phase, setPhase] = useState<"typing" | "results" | "pause">("typing");
  const timerRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  function clearTimers() {
    timerRef.current.forEach(clearTimeout);
    timerRef.current = [];
  }

  function addTimer(fn: () => void, delay: number) {
    timerRef.current.push(setTimeout(fn, delay));
  }

  useEffect(() => {
    const scenario = SCENARIOS[scenarioIdx];
    const domain = scenario.domain;
    let charIdx = 0;

    setTyped("");
    setVisibleLines([]);
    setPhase("typing");

    function typeNext() {
      if (charIdx <= domain.length) {
        setTyped(domain.slice(0, charIdx));
        charIdx++;
        addTimer(typeNext, TYPING_SPEED);
      } else {
        setPhase("results");
        scenario.lines.forEach((line, i) => {
          addTimer(() => setVisibleLines((prev) => [...prev, i]), line.delay + 200);
        });
        const lastDelay = scenario.lines[scenario.lines.length - 1].delay + 200;
        addTimer(() => {
          setPhase("pause");
          addTimer(() => {
            setScenarioIdx((prev) => (prev + 1) % SCENARIOS.length);
          }, PAUSE_AFTER);
        }, lastDelay + 400);
      }
    }

    addTimer(typeNext, 300);

    return clearTimers;
  }, [scenarioIdx]);

  const scenario = SCENARIOS[scenarioIdx];

  return (
    <div className="w-full">
      <div
        className="relative overflow-hidden rounded-xl font-mono text-sm"
        style={{
          background: "#0a0a0a",
          border: `1px solid ${marketing.borderStrong}`,
          boxShadow: `0 0 40px rgba(166,90,22,0.08), 0 20px 60px rgba(0,0,0,0.6)`,
        }}
      >
        {/* title bar */}
        <div className="px-4 py-2" style={{ background: marketing.accent }}>
          <span className="font-mono text-xs font-semibold" style={{ color: "#000" }}>
            seqr — zsh
          </span>
        </div>

        {/* content */}
        <div className="p-5 leading-6" style={{ minHeight: 280 }}>
          {/* prompt + typed domain */}
          <div>
            <span style={{ color: marketing.safe }}>{PROMPT}</span>
            <span style={{ color: marketing.accent }}>{typed}</span>
            {phase === "typing" && (
              <span
                className="inline-block w-2 h-4 ml-0.5 align-middle animate-pulse"
                style={{ background: marketing.accent }}
              />
            )}
          </div>

          {/* result lines */}
          {visibleLines.map((lineIdx) => {
            const line = scenario.lines[lineIdx];
            if (!line) return null;
            return (
              <div key={lineIdx} className="mt-0.5">
                {line.text === "" ? (
                  <span>&nbsp;</span>
                ) : (
                  colorLine(line.text, line.highlight)
                )}
              </div>
            );
          })}
        </div>
      </div>

      <p className="mt-3 text-center text-xs" style={{ color: marketing.textFaint }}>
        Example output.{" "}
        <a href="#try-it-live" style={{ color: marketing.accent }} className="hover:underline">
          See a live result below ↓
        </a>
      </p>
    </div>
  );
}
