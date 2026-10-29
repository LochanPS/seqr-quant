"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Wordmark } from "@/components/brand";

export default function RootError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="flex min-h-dvh flex-col px-6 py-8 sm:px-12">
      <Link href="/" aria-label="SeQr home">
        <Wordmark className="text-[26px]" />
      </Link>
      <div className="my-auto max-w-2xl py-16">
        <p className="eyebrow text-immediate">Error</p>
        <h1 className="mt-4 font-display text-5xl leading-none text-ink">Something broke on this page</h1>
        <p className="mt-4 break-words font-mono text-sm text-ink-2">{error.message || "Unknown error"}</p>
        <div className="mt-8 flex gap-2">
          <Button onClick={reset}>Try again</Button>
          <Button asChild variant="secondary">
            <Link href="/">Go home</Link>
          </Button>
        </div>
      </div>
    </main>
  );
}
