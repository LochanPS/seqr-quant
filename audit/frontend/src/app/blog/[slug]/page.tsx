import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";

export const dynamic = "force-dynamic";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface Post {
  slug: string;
  title: string;
  excerpt: string | null;
  body: string;
  tags: string[];
  published_at: string | null;
}

async function getPost(slug: string): Promise<Post | null> {
  try {
    const r = await fetch(`${API}/blog/${slug}`, { cache: "no-store" });
    if (!r.ok) return null;
    return r.json();
  } catch {
    return null;
  }
}

export async function generateMetadata({ params }: { params: { slug: string } }): Promise<Metadata> {
  const post = await getPost(params.slug);
  if (!post) return { title: "Not found — SeQr Labs" };
  return {
    title: `${post.title} — SeQr Labs`,
    description: post.excerpt || post.title,
    openGraph: { title: post.title, description: post.excerpt || post.title, type: "article" },
  };
}

export default async function BlogPostPage({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug);
  if (!post) notFound();

  return (
    <main style={{ background: "#000", color: "#EDE7DC", minHeight: "100vh" }}>
      <article className="mx-auto max-w-2xl px-6 py-24">
        <Link href="/blog" style={{ color: "#A65A16" }} className="text-sm font-semibold">← Blog</Link>
        <h1 className="font-display mt-6 text-4xl font-semibold tracking-tight">{post.title}</h1>
        {post.published_at && (
          <div className="mt-2 text-xs uppercase tracking-wide" style={{ color: "rgba(237,231,220,0.40)" }}>
            {new Date(post.published_at).toLocaleDateString()}
          </div>
        )}
        <div
          className="mt-8 whitespace-pre-wrap text-base leading-relaxed"
          style={{ color: "rgba(237,231,220,0.82)" }}
        >
          {post.body}
        </div>
      </article>
    </main>
  );
}
