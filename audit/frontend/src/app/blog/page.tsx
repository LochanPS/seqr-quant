import Link from "next/link";
import type { Metadata } from "next";
import { SiteHeader } from "@/components/site-header";
import { Footer } from "@/components/marketing/footer";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Blog",
  description: "Notes on post-quantum cryptography, Indian compliance and the SeQr research.",
};

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface PostItem {
  slug: string;
  title: string;
  excerpt: string | null;
  tags: string[];
  published_at: string | null;
}

async function getPosts(): Promise<{ posts: PostItem[]; error: boolean }> {
  try {
    const r = await fetch(`${API}/blog`, { cache: "no-store" });
    if (!r.ok) return { posts: [], error: true };
    return { posts: await r.json(), error: false };
  } catch {
    return { posts: [], error: true };
  }
}

const fmt = (d: string | null) => (d ? new Date(d).toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" }) : "Draft");

export default async function BlogIndex() {
  const { posts, error } = await getPosts();
  return (
    <div className="min-h-dvh bg-bg">
      <SiteHeader />
      <main className="mx-auto max-w-page px-5 pb-32 pt-16 sm:px-8">
        <p className="eyebrow">Notes from SeQr Labs</p>
        <h1 className="mt-4 font-display text-[clamp(3rem,8vw,6.5rem)] leading-[0.92] text-ink">Blog</h1>
        <p className="mt-5 max-w-xl text-[17px] text-ink-2">Post-quantum cryptography, the Indian regulatory picture, and what the measurements show.</p>

        <div className="mt-16 border-t border-ink">
          {error ? (
            <div className="py-12">
              <p className="font-display text-2xl text-ink">The blog is unavailable right now.</p>
              <p className="mt-2 text-ink-2">The publishing service did not answer. Try again in a moment.</p>
              <Link href="/blog" className="mt-4 inline-block text-sm text-ink link-underline">
                Retry
              </Link>
            </div>
          ) : posts.length === 0 ? (
            <div className="py-12">
              <p className="font-display text-2xl text-ink">No posts yet.</p>
              <p className="mt-2 text-ink-2">The first notes are being written.</p>
              <Link href="/" className="mt-4 inline-block text-sm text-ink link-underline">
                Back to the home page
              </Link>
            </div>
          ) : (
            <ol>
              {posts.map((p, i) => (
                <li key={p.slug} className="border-b border-rule">
                  <Link href={`/blog/${p.slug}`} className="group grid gap-4 py-8 md:grid-cols-[120px_1fr_200px] md:items-baseline">
                    <span className="font-mono text-xs text-ink-3">{String(posts.length - i).padStart(3, "0")}</span>
                    <span>
                      <span className="block font-display text-[clamp(1.6rem,3vw,2.4rem)] leading-tight text-ink decoration-1 underline-offset-[6px] group-hover:underline">{p.title}</span>
                      {p.excerpt && <span className="mt-2 block max-w-2xl text-ink-2">{p.excerpt}</span>}
                      {p.tags.length > 0 && (
                        <span className="mt-3 flex flex-wrap gap-1.5">
                          {p.tags.map((t) => (
                            <span key={t} className="rounded-xs border border-rule px-1.5 py-[1px] font-mono text-[11px] uppercase tracking-[0.06em] text-ink-2">
                              {t}
                            </span>
                          ))}
                        </span>
                      )}
                    </span>
                    <span className="font-mono text-xs text-ink-3 md:text-right">
                      {fmt(p.published_at)}
                      <span className="mt-2 block text-ink">Read</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ol>
          )}
        </div>
      </main>
      <Footer />
    </div>
  );
}
