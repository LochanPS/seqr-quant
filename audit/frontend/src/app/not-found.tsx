import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Wordmark } from "@/components/brand";

export default function NotFound() {
  return (
    <main className="flex min-h-dvh flex-col px-6 py-8 sm:px-12">
      <Link href="/" aria-label="SeQr home" className="w-fit">
        <Wordmark className="text-[26px]" />
      </Link>
      <div className="my-auto grid max-w-5xl gap-10 py-16 md:grid-cols-[auto_1fr] md:items-end">
        <p className="font-display text-[clamp(6rem,18vw,13rem)] leading-[0.8] text-ink tabular">404</p>
        <div className="border-t border-ink pt-5">
          <p className="eyebrow">No record</p>
          <h1 className="mt-3 font-display text-3xl text-ink">Page not found</h1>
          <p className="mt-2 max-w-md text-ink-2">The address does not match any page. It may have moved, or the link was mistyped.</p>
          <div className="mt-6 flex flex-wrap gap-2">
            <Button asChild>
              <Link href="/">Go home</Link>
            </Button>
            <Button asChild variant="secondary">
              <Link href="/dashboard/posture">Open the dashboard</Link>
            </Button>
          </div>
        </div>
      </div>
    </main>
  );
}
