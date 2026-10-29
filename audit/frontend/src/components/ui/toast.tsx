"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { cn } from "@/lib/utils";
import { IconClose } from "@/components/icons";

type Tone = "neutral" | "success" | "error";
type Toast = { id: number; title: string; description?: string; tone: Tone; duration: number };
type ToastInput = { title: string; description?: string; tone?: Tone; duration?: number };

const Ctx = createContext<((t: ToastInput) => void) | null>(null);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seq = useRef(0);

  const push = useCallback((t: ToastInput) => {
    const id = ++seq.current;
    setToasts((xs) => [...xs.slice(-3), { id, tone: "neutral", duration: 5000, ...t }]);
  }, []);
  const dismiss = (id: number) => setToasts((xs) => xs.filter((x) => x.id !== id));

  return (
    <Ctx.Provider value={push}>
      {children}
      <div
        aria-live="polite"
        aria-relevant="additions"
        className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2"
      >
        <AnimatePresence initial={false}>
          {toasts.map((t) => (
            <ToastItem key={t.id} toast={t} onDone={() => dismiss(t.id)} />
          ))}
        </AnimatePresence>
      </div>
    </Ctx.Provider>
  );
}

function ToastItem({ toast, onDone }: { toast: Toast; onDone: () => void }) {
  const [paused, setPaused] = useState(false);
  const remaining = useRef(toast.duration);
  const startedAt = useRef(Date.now());

  useEffect(() => {
    if (paused) return;
    startedAt.current = Date.now();
    const t = setTimeout(onDone, remaining.current);
    return () => {
      clearTimeout(t);
      remaining.current -= Date.now() - startedAt.current;
    };
  }, [paused, onDone]);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 24, transition: { duration: 0.16 } }}
      transition={{ type: "spring", stiffness: 420, damping: 34 }}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      role={toast.tone === "error" ? "alert" : "status"}
      className={cn(
        "pointer-events-auto relative overflow-hidden border bg-bg",
        toast.tone === "error" ? "border-immediate" : toast.tone === "success" ? "border-safe" : "border-ink"
      )}
    >
      <div className="flex items-start gap-3 px-4 py-3">
        <span
          aria-hidden
          className={cn(
            "mt-1.5 h-2 w-2 shrink-0",
            toast.tone === "error" ? "bg-immediate" : toast.tone === "success" ? "bg-safe" : "bg-ink"
          )}
        />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-ink">{toast.title}</p>
          {toast.description && <p className="mt-0.5 break-words text-[13px] text-ink-2">{toast.description}</p>}
        </div>
        <button
          onClick={onDone}
          aria-label="Dismiss notification"
          className="-mr-1 inline-flex h-6 w-6 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-ink"
        >
          <IconClose size={14} />
        </button>
      </div>
      <span
        aria-hidden
        className="absolute bottom-0 left-0 h-px w-full origin-left bg-ink"
        style={{
          animation: `rule-shrink ${toast.duration}ms linear forwards`,
          animationPlayState: paused ? "paused" : "running",
        }}
      />
    </motion.div>
  );
}

export function useToast() {
  const push = useContext(Ctx);
  if (!push) throw new Error("useToast must be used inside ToastProvider");
  return push;
}
