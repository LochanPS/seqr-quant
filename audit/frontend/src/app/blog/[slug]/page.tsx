import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { SiteHeader } from "@/components/site-header";
import { Footer } from "@/components/marketing/footer";
import { Markdown } from "@/components/markdown";
import { ReadingProgress } from "./reading-progress";

export const dynamic = "force-dynamic";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface Post {
  slug: string;
  title: string;
  excerpt: string | null;
  body: string;
  tags: string[];
  author_email?: string | null;
  published_at: string | null;
}

async function getPost(slug: string): Promise<Post | null> {
  try {
    const r = await fetch(`${API}/blog/${encodeURIComponent(slug)}`, { cache: "no-store" });
    if (!r.ok) return null;
    return r.json();
  } catch {
    return null;
  }
}

export async function generateMetadata({ params }: { params: { slug: string } }): Promise<Metadata> {
  const post = await getPost(params.slug);
  if (!post) return { title: "Post not found" };
  return {
    title: post.title,
    description: post.excerpt || post.title,
    openGraph: { title: post.title, description: post.excerpt || post.title, type: "article" },
  };
}

export default async function PostPage({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug);
  if (!post) notFound();
  const words = post.body.split(/\s+/).length;
  return (
    <div className="min-h-dvh bg-bg">
      <ReadingProgress />
      <SiteHeader />
      <main className="mx-auto max-w-page px-5 pb-32 pt-12 sm:px-8">
        <Link href="/blog" className="text-sm text-ink-2 link-underline">
          All posts
        </Link>
        <header className="mt-10 max-w-4xl border-b border-ink pb-10">
          <p className="eyebrow">
            {post.published_at ? new Date(post.published_at).toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" }) : "Draft"} ·{" "}
            {Math.max(1, Math.round(words / 220))} min read
          </p>
          <h1 className="mt-5 font-display text-[clamp(2.6rem,6vw,5rem)] leading-[0.98] text-ink">{post.title}</h1>
          {post.excerpt && <p className="mt-6 max-w-2xl text-[19px] leading-relaxed text-ink-2">{post.excerpt}</p>}
          {post.tags.length > 0 && (
            <div className="mt-6 flex flex-wrap gap-1.5">
              {post.tags.map((t) => (
                <span key={t} className="rounded-xs border border-rule px-1.5 py-[1px] font-mono text-[11px] uppercase tracking-[0.06em] text-ink-2">
                  {t}
                </span>
              ))}
            </div>
          )}
        </header>
        <article className="mx-auto mt-12 max-w-measure">
          <Markdown source={post.body} />
        </article>
        <div className="mx-auto mt-16 max-w-measure border-t border-ink pt-6">
          <Link href="/blog" className="text-sm text-ink link-underline">
            Back to all posts
          </Link>
        </div>
      </main>
      <Footer />
    </div>
  );
}
