"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import { Loader2, ArrowRight } from "lucide-react";
import { AuthShell } from "@/components/auth/AuthShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, setToken } from "@/lib/api";
import { fadeUp, stagger } from "@/lib/motion";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api.auth.login({ email, password });
      if (res.mfa_required) {
        setError("MFA is enabled for this account but not supported in this build.");
        return;
      }
      setToken(res.access_token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell>
      <motion.div variants={stagger(5, 0.08)} initial="hidden" animate="visible">
        <motion.div variants={fadeUp} className="mb-8 lg:hidden">
          {/* spacer for mobile branding handled by shell */}
        </motion.div>

        <motion.h1 variants={fadeUp} className="text-3xl font-semibold tracking-tight">
          Welcome back
        </motion.h1>
        <motion.p variants={fadeUp} className="mt-2 text-sm text-muted-foreground">
          Sign in to your SeQr Labs workspace.
        </motion.p>

        <motion.form
          onSubmit={onSubmit}
          className="mt-8 space-y-4"
          animate={error ? { x: [0, -8, 8, -6, 6, -3, 3, 0] } : {}}
          transition={{ duration: 0.45 }}
        >
          <motion.div variants={fadeUp} className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </motion.div>

          <motion.div variants={fadeUp} className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </motion.div>

          {error && (
            <p className="text-sm text-vulnerable">{error}</p>
          )}

          <motion.div variants={fadeUp}>
            <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
              <Button
                type="submit"
                className="w-full hover:glow-quantum"
                disabled={loading}
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    Sign in <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </Button>
            </motion.div>
          </motion.div>
        </motion.form>

        <motion.p
          variants={fadeUp}
          className="mt-6 text-center text-sm text-muted-foreground"
        >
          No account yet?{" "}
          <Link href="/register" className="font-medium text-quantum hover:underline">
            Create one
          </Link>
        </motion.p>
      </motion.div>
    </AuthShell>
  );
}
