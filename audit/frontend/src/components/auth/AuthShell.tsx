"use client";

import { motion } from "framer-motion";
import { Logo } from "@/components/Logo";

export function AuthShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen w-full flex-col items-center justify-center bg-background px-6">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        className="w-full max-w-sm"
      >
        <div className="mb-10 flex justify-center">
          <Logo />
        </div>
        {children}
      </motion.div>
    </div>
  );
}
