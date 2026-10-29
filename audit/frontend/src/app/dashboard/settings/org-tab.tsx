"use client";

import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { errMsg, formatDate } from "@/lib/utils";
import { useOrg } from "@/lib/hooks";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { BlockSkeleton, ErrorState } from "@/components/ui/feedback";
import { Chip } from "@/components/ui/marks";
import { useToast } from "@/components/ui/toast";

const SECTORS = ["banking", "fintech", "insurance", "healthcare", "telecom", "government", "saas", "energy", "other"];

export function OrgTab() {
  const org = useOrg();
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [sector, setSector] = useState("");

  useEffect(() => {
    if (org.data) {
      setName(org.data.name);
      setSector(org.data.sector ?? "");
    }
  }, [org.data]);

  const dirty = !!org.data && (name.trim() !== org.data.name || sector.trim() !== (org.data.sector ?? ""));
  const save = useMutation({
    mutationFn: () => api.org.update({ name: name.trim(), sector: sector.trim() }),
    onSuccess: (o) => {
      qc.setQueryData(["org"], o);
      toast({ title: "Organisation saved", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not save", description: errMsg(e), tone: "error" }),
  });

  if (org.isLoading) return <BlockSkeleton lines={6} className="max-w-xl" />;
  if (org.isError) return <ErrorState message={errMsg(org.error)} onRetry={() => org.refetch()} />;
  const o = org.data!;

  return (
    <div className="grid gap-12 lg:grid-cols-[1fr_320px]">
      <form
        className="max-w-xl space-y-6"
        onSubmit={(e) => {
          e.preventDefault();
          if (dirty && name.trim()) save.mutate();
        }}
      >
        <Field label="Organisation name" error={!name.trim() ? "A name is required." : undefined}>
          {({ id, invalid, describedBy }) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} aria-invalid={invalid} aria-describedby={describedBy} />}
        </Field>
        <Field label="Sector" hint="Used to weight compliance frameworks, for example SEBI CSCRF for capital markets.">
          {({ id, describedBy }) => (
            <>
              <Input id={id} list="sectors" value={sector} onChange={(e) => setSector(e.target.value)} placeholder="banking" aria-describedby={describedBy} />
              <datalist id="sectors">
                {SECTORS.map((s) => (
                  <option key={s} value={s} />
                ))}
              </datalist>
            </>
          )}
        </Field>
        <div className="flex gap-2 border-t border-rule pt-5">
          <Button type="submit" pending={save.isPending} pendingLabel="Saving" disabled={!dirty || !name.trim()}>
            Save changes
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={!dirty}
            onClick={() => {
              setName(o.name);
              setSector(o.sector ?? "");
            }}
          >
            Discard
          </Button>
        </div>
      </form>

      <dl className="border-t border-ink">
        {[
          ["Plan", <Chip key="p">{o.plan}</Chip>],
          ["Quantum risk score", <span key="r" className="font-mono">{o.quantum_risk_score ?? "not computed"}</span>],
          ["Created", formatDate(o.created_at)],
          ["License expires", o.license_expires_at ? formatDate(o.license_expires_at) : "no expiry on record"],
          ["Workspace id", <span key="i" className="break-all font-mono text-xs">{o.id}</span>],
        ].map(([k, v]) => (
          <div key={String(k)} className="border-b border-rule py-3">
            <dt className="eyebrow">{k}</dt>
            <dd className="mt-1 text-sm text-ink">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
