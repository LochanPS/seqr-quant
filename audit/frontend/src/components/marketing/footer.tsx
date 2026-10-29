import Link from "next/link";
import { Wordmark } from "@/components/brand";
import { IconGitHub, IconLinkedIn } from "@/components/icons";
import { RESEARCH_URL } from "./constants";

const LINKS = [
  { label: "Blog", href: "/blog" },
  { label: "Privacy", href: "/privacy" },
  { label: "Terms", href: "/terms" },
  { label: "Sign in", href: "/login" },
  { label: "Create account", href: "/register" },
];

export function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="bg-bg">
      <div className="mx-auto max-w-page px-5 pb-10 pt-16 sm:px-8">
        <div className="grid gap-10 border-b border-rule pb-12 md:grid-cols-[1fr_auto]">
          <div>
            <Wordmark className="text-[44px]" labs />
            <p className="mt-4 max-w-sm text-sm text-ink-2">Post-quantum cryptography compliance, built in India.</p>
          </div>
          <nav aria-label="Footer" className="grid grid-cols-2 gap-x-12 gap-y-3 sm:grid-cols-3">
            {LINKS.map((l) => (
              <Link key={l.href} href={l.href} className="text-sm text-ink-2 transition-colors duration-micro hover:text-ink">
                {l.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-4 pt-6">
          <p className="font-mono text-[11px] text-ink-3">© {year} SeQr Labs. All rights reserved.</p>
          <div className="flex items-center gap-1">
            <a href="https://linkedin.com/company/seqrlabs" target="_blank" rel="noopener noreferrer" aria-label="SeQr Labs on LinkedIn" className="inline-flex h-10 w-10 items-center justify-center text-ink-2 transition-colors duration-micro hover:text-ink">
              <IconLinkedIn size={18} />
            </a>
            <a href={RESEARCH_URL} target="_blank" rel="noopener noreferrer" aria-label="SeQr research on GitHub" className="inline-flex h-10 w-10 items-center justify-center text-ink-2 transition-colors duration-micro hover:text-ink">
              <IconGitHub size={18} />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
