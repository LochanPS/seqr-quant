"use client";

import Link from "next/link";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type BlogPost } from "@/lib/api";
import { errMsg } from "@/lib/utils";
import { PageHeader, RelTime, Section, Segmented } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/field";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/feedback";
import { Chip, StatusChip } from "@/components/ui/marks";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";
import { Markdown } from "@/components/markdown";
import { OperatorGate } from "@/components/admin/operator-gate";
import { IconExternal } from "@/components/icons";

type Draft = { id: string | null; title: string; excerpt: string; body: string; tags: string };
const EMPTY: Draft = { id: null, title: "", excerpt: "", body: "", tags: "" };

function Cms() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const posts = useQuery({ queryKey: ["admin-posts"], queryFn: api.admin.posts });
  const [d, setD] = useState<Draft>(EMPTY);
  const [pane, setPane] = useState<"write" | "preview">("write");

  const tags = d.tags
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  const done = (title: string) => {
    qc.invalidateQueries({ queryKey: ["admin-posts"] });
    toast({ title, tone: "success" });
  };

  const save = useMutation({
    mutationFn: (status: "draft" | "published") => {
      const data: Partial<BlogPost> = { title: d.title.trim(), excerpt: d.excerpt.trim() || null, body: d.body, tags, status };
      return d.id ? api.admin.updatePost(d.id, data) : api.admin.createPost(data);
    },
    onSuccess: (p) => {
      done(p.status === "published" ? "Post published" : "Draft saved");
      setD(EMPTY);
      setPane("write");
    },
    onError: (e) => toast({ title: "Could not save the post", description: errMsg(e), tone: "error" }),
  });
  const setStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => api.admin.updatePost(id, { status }),
    onSuccess: (p) => done(p.status === "published" ? "Post published" : "Post unpublished"),
    onError: (e) => toast({ title: "Could not change status", description: errMsg(e), tone: "error" }),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.admin.deletePost(id),
    onSuccess: () => done("Post deleted"),
    onError: (e) => toast({ title: "Could not delete", description: errMsg(e), tone: "error" }),
  });

  return (
    <div className="space-y-12">
      <PageHeader
        eyebrow="Operator console"
        title="Blog and CMS"
        description="Write in markdown, preview, then publish to /blog."
        actions={
          <Button asChild variant="ghost">
            <Link href="/admin">Operator console</Link>
          </Button>
        }
      />

      <Section index="01" title={d.id ? "Edit post" : "New post"} actions={d.id ? <Button variant="ghost" size="sm" onClick={() => setD(EMPTY)}>Start a new post instead</Button> : undefined}>
        <form
          className="space-y-5 border-t border-ink pt-6"
          onSubmit={(e) => {
            e.preventDefault();
            if (d.title.trim()) save.mutate("draft");
          }}
        >
          <div className="grid gap-5 lg:grid-cols-2">
            <Field label="Title">{({ id }) => <Input id={id} value={d.title} onChange={(e) => setD({ ...d, title: e.target.value })} placeholder="PQC is coming to Indian fintech" />}</Field>
            <Field label="Excerpt" hint="One or two sentences. Used for search results and the blog index.">
              {({ id, describedBy }) => <Input id={id} value={d.excerpt} onChange={(e) => setD({ ...d, excerpt: e.target.value })} placeholder="Why SEBI CSCRF makes a CBOM urgent" aria-describedby={describedBy} />}
            </Field>
          </div>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[13px] font-medium text-ink-2">Body</span>
              <Segmented
                label="Editor pane"
                value={pane}
                onChange={setPane}
                options={[
                  { value: "write", label: "Write" },
                  { value: "preview", label: "Preview" },
                ]}
              />
            </div>
            <div className="grid gap-px border border-rule bg-rule xl:grid-cols-2">
              <Textarea
                aria-label="Body in markdown"
                value={d.body}
                onChange={(e) => setD({ ...d, body: e.target.value })}
                placeholder={"## Heading\n\nYour post, in markdown."}
                className={`${pane === "preview" ? "hidden xl:block" : ""} min-h-[360px] border-0 font-mono text-[13px]`}
              />
              <div className={`${pane === "write" ? "hidden xl:block" : ""} min-h-[360px] overflow-auto bg-bg p-5`}>
                {d.body.trim() ? <Markdown source={d.body} /> : <p className="text-sm text-ink-3">The preview appears here as you write.</p>}
              </div>
            </div>
          </div>
          <Field label="Tags" hint="Comma-separated.">
            {({ id, describedBy }) => (
              <div>
                <Input id={id} value={d.tags} onChange={(e) => setD({ ...d, tags: e.target.value })} placeholder="pqc, india, sebi" aria-describedby={describedBy} />
                {tags.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {tags.map((t) => (
                      <Chip key={t}>{t}</Chip>
                    ))}
                  </div>
                )}
              </div>
            )}
          </Field>
          <div className="flex gap-2 border-t border-rule pt-5">
            <Button type="submit" variant="secondary" disabled={!d.title.trim()} pending={save.isPending && save.variables === "draft"} pendingLabel="Saving">
              Save draft
            </Button>
            <Button type="button" disabled={!d.title.trim()} onClick={() => save.mutate("published")} pending={save.isPending && save.variables === "published"} pendingLabel="Publishing">
              Publish
            </Button>
          </div>
        </form>
      </Section>

      <Section index="02" title="All posts">
        {posts.isLoading ? (
          <TableSkeleton cols={4} rows={3} />
        ) : posts.isError ? (
          <ErrorState message={errMsg(posts.error)} onRetry={() => posts.refetch()} />
        ) : !posts.data?.length ? (
          <EmptyState title="No posts yet" body="Write the first one above." />
        ) : (
          <ul className="border-t border-ink">
            {posts.data.map((p) => (
              <li key={p.id} className="grid gap-3 border-b border-rule py-4 md:grid-cols-[1fr_auto] md:items-center">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-3">
                    <span className="font-display text-xl text-ink">{p.title}</span>
                    <StatusChip value={p.status} />
                  </p>
                  <p className="mt-1 font-mono text-[11px] text-ink-3">
                    /{p.slug} · <RelTime value={p.published_at ?? p.created_at} />
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {p.status === "published" && (
                    <Button asChild variant="ghost" size="sm">
                      <Link href={`/blog/${p.slug}`} target="_blank">
                        View <IconExternal size={12} />
                      </Link>
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setD({ id: p.id, title: p.title, excerpt: p.excerpt ?? "", body: p.body, tags: p.tags.join(", ") });
                      window.scrollTo({ top: 0, behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
                    }}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    pending={setStatus.isPending && setStatus.variables?.id === p.id}
                    pendingLabel="Saving"
                    onClick={() => setStatus.mutate({ id: p.id, status: p.status === "published" ? "draft" : "published" })}
                  >
                    {p.status === "published" ? "Unpublish" : "Publish"}
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    pending={del.isPending && del.variables === p.id}
                    pendingLabel="Deleting"
                    onClick={async () => {
                      const ok = await confirm({ title: "Delete this post?", subject: p.title, body: "It is removed from the blog and cannot be recovered.", confirmLabel: "Delete post" });
                      if (ok) del.mutate(p.id);
                    }}
                  >
                    Delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

export default function AdminBlogPage() {
  return (
    <OperatorGate>
      <Cms />
    </OperatorGate>
  );
}
