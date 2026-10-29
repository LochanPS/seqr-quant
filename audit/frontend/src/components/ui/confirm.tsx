"use client";

import { createContext, useCallback, useContext, useRef, useState } from "react";
import { Dialog, DialogContent, DialogFooter } from "./dialog";
import { Button } from "./button";

type ConfirmOptions = {
  title: string;
  /** The specific thing being acted on, shown in mono so the user knows exactly what goes. */
  subject?: string;
  body?: React.ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
};

type ConfirmFn = (opts: ConfirmOptions) => Promise<boolean>;

const Ctx = createContext<ConfirmFn | null>(null);

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [opts, setOpts] = useState<ConfirmOptions | null>(null);
  const resolver = useRef<((v: boolean) => void) | null>(null);

  const confirm = useCallback<ConfirmFn>((o) => {
    setOpts(o);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  const settle = (v: boolean) => {
    resolver.current?.(v);
    resolver.current = null;
    setOpts(null);
  };

  return (
    <Ctx.Provider value={confirm}>
      {children}
      <Dialog open={!!opts} onOpenChange={(o) => !o && settle(false)}>
        {opts && (
          <DialogContent title={opts.title}>
            {opts.subject && (
              <p className="mb-3 break-all border border-rule bg-surface px-3 py-2 font-mono text-sm text-ink">
                {opts.subject}
              </p>
            )}
            {opts.body && <div className="text-sm text-ink-2">{opts.body}</div>}
            <DialogFooter>
              <Button variant="ghost" onClick={() => settle(false)}>
                Cancel
              </Button>
              <Button
                variant={opts.tone === "primary" ? "primary" : "danger"}
                onClick={() => settle(true)}
                autoFocus
              >
                {opts.confirmLabel ?? "Confirm"}
              </Button>
            </DialogFooter>
          </DialogContent>
        )}
      </Dialog>
    </Ctx.Provider>
  );
}

export function useConfirm() {
  const fn = useContext(Ctx);
  if (!fn) throw new Error("useConfirm must be used inside ConfirmProvider");
  return fn;
}
