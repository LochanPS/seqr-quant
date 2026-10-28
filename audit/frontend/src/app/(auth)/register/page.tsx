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

export default function RegisterPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [orgName, setOrgName] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api.auth.register({
        name,
        email,
        org_name: orgName,
        password,
      });
      setToken(res.access_token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell>
      <motion.div variants={stagger(6, 0.07)} initial="hidden" animate="visible">
        <motion.h1 variants={fadeUp} className="text-3xl font-semibold tracking-tight">
          Create your workspace
        </motion.h1>
        <motion.p variants={fadeUp} className="mt-2 text-sm text-muted-foreground">
          Start auditing your cryptography in minutes.
        </motion.p>

        <motion.form
          onSubmit={onSubmit}
          className="mt-8 space-y-4"
          animate={error ? { x: [0, -8, 8, -6, 6, -3, 3, 0] } : {}}
          transition={{ duration: 0.45 }}
        >
          <motion.div variants={fadeUp} className="space-y-2">
            <Label htmlFor="name">Full name</Label>
            <Input
              id="name"
              placeholder="Ada Lovelace"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </motion.div>

          <motion.div variants={fadeUp} className="space-y-2">
            <Label htmlFor="org">Organisation</Label>
            <Input
              id="org"
              placeholder="Acme Corp"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              required
            />
          </motion.div>

          <motion.div variants={fadeUp} className="space-y-2">
            <Label htmlFor="email">Work email</Label>
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
              autoComplete="new-password"
              placeholder="At least 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={8}
              required
            />
          </motion.div>

          {error && <p className="text-sm text-vulnerable">{error}</p>}

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
                    Create account <ArrowRight className="h-4 w-4" />
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
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-quantum hover:underline">
            Sign in
          </Link>
        </motion.p>
      </motion.div>
    </AuthShell>
  );
}
