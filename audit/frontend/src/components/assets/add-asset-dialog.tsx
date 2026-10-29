"use client";

import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "motion/react";
import { api } from "@/lib/api";
import { cn, errMsg } from "@/lib/utils";
import { ASSET_TYPES, SENSITIVITIES } from "@/lib/domain";
import { Dialog, DialogContent, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Field, Input, Label } from "@/components/ui/field";
import { useToast } from "@/components/ui/toast";

// Accept a bare hostname, optionally with :port. Strip a pasted scheme or path first.
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(:\d{1,5})?$|^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/i;

function normaliseHost(raw: string) {
  return raw.trim().replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "");
}

export function AddAssetDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [type, setType] = useState<string>("domain");
  const [host, setHost] = useState("");
  const [sens, setSens] = useState<string>("confidential");
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    if (!open) {
      setName("");
      setType("domain");
      setHost("");
      setSens("confidential");
      setTouched(false);
    }
  }, [open]);

  const clean = normaliseHost(host);
  const hostOk = HOST_RE.test(clean);

  const create = useMutation({
    mutationFn: () => api.assets.create({ type, identifier: clean, name: name.trim() || undefined, data_sensitivity: sens }),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["graph-assets"] });
      qc.invalidateQueries({ queryKey: ["pipeline"] });
      toast({ title: "Asset added", description: `${a.name || a.identifier} is ready to scan.`, tone: "success" });
      onOpenChange(false);
    },
    onError: (e) => toast({ title: "Could not add the asset", description: errMsg(e), tone: "error" }),
  });

  const placeholder = ASSET_TYPES.find((t) => t.value === type)?.placeholder ?? "api.company.com";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Add an asset" description="Anything that speaks TLS or SSH. SeQr probes it from the outside; nothing is installed." wide>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setTouched(true);
            if (hostOk) create.mutate();
          }}
          className="space-y-6"
        >
          <div>
            <Label>Asset type</Label>
            <div role="radiogroup" aria-label="Asset type" className="grid grid-cols-2 gap-px border border-rule bg-rule sm:grid-cols-4">
              {ASSET_TYPES.map((t) => {
                const on = t.value === type;
                return (
                  <button
                    key={t.value}
                    type="button"
                    role="radio"
                    aria-checked={on}
                    onClick={() => setType(t.value)}
                    className={cn(
                      "relative h-12 bg-bg px-3 text-left text-[13px] transition-colors duration-micro",
                      on ? "text-bg" : "text-ink-2 hover:text-ink"
                    )}
                  >
                    {on && <motion.span layoutId="asset-type" className="absolute inset-0 bg-ink" transition={{ type: "spring", stiffness: 520, damping: 42 }} />}
                    <span className="relative">{t.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Host" error={touched && !hostOk ? "Enter a hostname or IP, for example api.company.com" : undefined}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  onBlur={() => setTouched(true)}
                  placeholder={placeholder}
                  autoFocus
                  spellCheck={false}
                  autoCapitalize="off"
                  className="font-mono"
                  aria-invalid={invalid}
                  aria-describedby={describedBy}
                />
              )}
            </Field>
            <Field label="Name" hint="Optional. Shown in place of the host.">
              {({ id, describedBy }) => (
                <Input id={id} value={name} onChange={(e) => setName(e.target.value)} placeholder="Production API" aria-describedby={describedBy} />
              )}
            </Field>
          </div>

          <div>
            <Label>Data sensitivity</Label>
            <div role="radiogroup" aria-label="Data sensitivity" className="flex flex-wrap gap-2">
              {SENSITIVITIES.map((s) => {
                const on = s.value === sens;
                return (
                  <button
                    key={s.value}
                    type="button"
                    role="radio"
                    aria-checked={on}
                    onClick={() => setSens(s.value)}
                    className={cn(
                      "h-9 border px-3 text-[13px] transition-colors duration-micro",
                      on ? "border-ink bg-ink text-bg" : "border-rule text-ink-2 hover:border-ink hover:text-ink"
                    )}
                  >
                    {s.label}
                  </button>
                );
              })}
            </div>
            <p className="mt-2 text-xs text-ink-3">Sensitivity and shelf life drive the harvest now, decrypt later score.</p>
          </div>

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" pending={create.isPending} pendingLabel="Adding" disabled={!host.trim()}>
              Add asset
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
