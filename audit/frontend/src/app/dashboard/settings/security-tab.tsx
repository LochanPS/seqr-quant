"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import { api } from "@/lib/api";
import { errMsg } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { BlockSkeleton } from "@/components/ui/feedback";
import { Stamp } from "@/components/ui/marks";
import { CopyButton } from "@/components/ui/code";
import { useToast } from "@/components/ui/toast";
import { OtpInput } from "@/components/auth/otp-input";
import { IconShield } from "@/components/icons";

/** The current user's MFA flag lives on the member list; find "me" by matching the token's subject. */
function useMe() {
  return useQuery({
    queryKey: ["me-mfa"],
    queryFn: async () => {
      const token = typeof window !== "undefined" ? window.localStorage.getItem("seqr_token") : null;
      const sub = token ? JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).sub : null;
      try {
        const users = await api.org.users();
        return users.find((u) => u.id === sub) ?? null;
      } catch {
        return null;
      }
    },
  });
}

export function SecurityTab() {
  const me = useMe();
  const qc = useQueryClient();
  const toast = useToast();
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [enabled, setEnabled] = useState(false);

  const begin = useMutation({
    mutationFn: api.auth.mfaSetup,
    onSuccess: (r) => setSetup({ secret: r.secret, uri: r.uri || r.qr_code }),
    onError: (e) => toast({ title: "Could not start 2FA setup", description: errMsg(e), tone: "error" }),
  });
  const verify = useMutation({
    mutationFn: (c: string) => api.auth.mfaVerify(c),
    onSuccess: () => {
      setEnabled(true);
      setSetup(null);
      setCode("");
      qc.invalidateQueries({ queryKey: ["me-mfa"] });
      qc.invalidateQueries({ queryKey: ["org-users"] });
      toast({ title: "Two-factor authentication is on", tone: "success" });
    },
    onError: (e) => {
      setCode("");
      toast({ title: "That code did not match", description: errMsg(e), tone: "error" });
    },
  });

  const on = enabled || !!me.data?.mfa_enabled;

  return (
    <div className="grid gap-12 lg:grid-cols-[1fr_1fr]">
      <section>
        <p className="eyebrow">Two-factor authentication</p>
        <h2 className="mt-2 font-display text-[1.6rem] leading-tight text-ink">Ask for a code at every sign-in</h2>
        <p className="mt-2 max-w-md text-sm text-ink-2">
          Use any TOTP authenticator: 1Password, Google Authenticator, Authy or your password manager. Once on, sign-in asks for a six digit code after your password.
        </p>
        <div className="mt-6">
          {me.isLoading ? (
            <BlockSkeleton lines={2} className="max-w-xs" />
          ) : on ? (
            <Stamp tone="safe" value="on">
              <IconShield size={14} /> 2FA enabled
            </Stamp>
          ) : !setup ? (
            <Button onClick={() => begin.mutate()} pending={begin.isPending} pendingLabel="Preparing">
              Set up 2FA
            </Button>
          ) : null}
        </div>
      </section>

      {setup && !on && (
        <section className="border border-ink p-6">
          <ol className="space-y-6">
            <li>
              <p className="font-mono text-xs text-ink-3">01 · Scan</p>
              <div className="mt-3 inline-block bg-[#EFEAE0] p-3">
                <QRCodeSVG value={setup.uri} size={168} bgColor="#EFEAE0" fgColor="#16140F" level="M" marginSize={0} />
              </div>
            </li>
            <li>
              <p className="font-mono text-xs text-ink-3">02 · Or enter the secret</p>
              <div className="mt-2 flex items-center gap-3 border border-rule bg-surface px-3 py-2">
                <code className="min-w-0 flex-1 break-all font-mono text-sm text-ink">{setup.secret}</code>
                <CopyButton text={setup.secret} />
              </div>
            </li>
            <li>
              <p className="font-mono text-xs text-ink-3">03 · Confirm with a code</p>
              <div className="mt-3">
                <OtpInput value={code} onChange={setCode} onComplete={(c) => verify.mutate(c)} disabled={verify.isPending} />
              </div>
              <div className="mt-4 flex gap-2">
                <Button onClick={() => verify.mutate(code)} disabled={code.length !== 6} pending={verify.isPending} pendingLabel="Verifying">
                  Turn on 2FA
                </Button>
                <Button variant="ghost" onClick={() => setSetup(null)}>
                  Cancel
                </Button>
              </div>
            </li>
          </ol>
        </section>
      )}
    </div>
  );
}
