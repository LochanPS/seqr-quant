import Link from "next/link";

export const dynamic = "force-dynamic";
export const metadata = {
  title: "Blog — SeQr Labs",
  description: "Post-quantum cryptography, compliance, and research from SeQr Labs.",
};

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

interface PostItem {
  slug: string;
  title: string;
  excerpt: string | null;
  tags: string[];
  published_at: string | null;
}

async function getPosts(): Promise<PostItem[]> {
  try {
    const r = await fetch(`${API}/blog`, { cache: "no-store" });
    if (!r.ok) return [];
    return r.json();
  } catch {
    return [];
  }
}

export default async function BlogIndex() {
  const posts = await getPosts();
  return (
    <main style={{ background: "#000", color: "#EDE7DC", minHeight: "100vh" }}>
      <div className="mx-auto max-w-3xl px-6 py-24">
        <Link href="/" style={{ color: "#A65A16" }} className="text-sm font-semibold">← SeQr Labs</Link>
        <h1 className="font-display mt-6 text-4xl font-semibold tracking-tight">Blog</h1>
        <p className="mt-3" style={{ color: "rgba(237,231,220,0.62)" }}>
          Post-quantum cryptography, Indian compliance, and our research.
        </p>

        {posts.length === 0 ? (
          <p className="mt-12" style={{ color: "rgba(237,231,220,0.45)" }}>No posts yet.</p>
        ) : (
          <div className="mt-12 space-y-8">
            {posts.map((p) => (
              <article key={p.slug} className="border-b pb-8" style={{ borderColor: "rgba(237,231,220,0.10)" }}>
                <Link href={`/blog/${p.slug}`}>
                  <h2 className="text-2xl font-semibold tracking-tight hover:opacity-80">{p.title}</h2>
                </Link>
                {p.published_at && (
                  <div className="mt-1 text-xs uppercase tracking-wide" style={{ color: "rgba(237,231,220,0.40)" }}>
                    {new Date(p.published_at).toLocaleDateString()}
                  </div>
                )}
                {p.excerpt && <p className="mt-3" style={{ color: "rgba(237,231,220,0.62)" }}>{p.excerpt}</p>}
                <Link href={`/blog/${p.slug}`} className="mt-3 inline-block text-sm" style={{ color: "#A65A16" }}>
                  Read →
                </Link>
              </article>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
