import Link from "next/link";
import { Wordmark } from "@/components/brand";

/** Slim header for secondary public pages (blog, post). */
export function SiteHeader() {
  return (
    <header className="sticky top-0 z-30 border-b border-ink bg-bg">
      <div className="mx-auto flex h-14 max-w-page items-center justify-between px-5 sm:px-8">
        <Link href="/" aria-label="SeQr home">
          <Wordmark className="text-[24px]" labs />
        </Link>
        <nav className="flex items-center gap-5 text-sm">
          <Link href="/blog" className="text-ink-2 transition-colors duration-micro hover:text-ink">
            Blog
          </Link>
          <Link href="/login" className="text-ink-2 transition-colors duration-micro hover:text-ink">
            Sign in
          </Link>
          <Link href="/#try-it-live" className="hidden bg-ink px-3 py-1.5 text-bg transition-colors duration-micro hover:bg-ink-2 sm:inline-block">
            Scan a domain
          </Link>
        </nav>
      </div>
    </header>
  );
}
