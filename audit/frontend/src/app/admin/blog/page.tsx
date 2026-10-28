"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { api, type BlogPost } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/components/ui/toast";

export default function AdminBlogPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [title, setTitle] = useState("");
  const [excerpt, setExcerpt] = useState("");
  const [body, setBody] = useState("");
  const [tags, setTags] = useState("");

  const posts = useQuery({ queryKey: ["admin-posts"], queryFn: api.admin.posts });

  const reset = () => { setTitle(""); setExcerpt(""); setBody(""); setTags(""); };
  const invalidate = () => qc.invalidateQueries({ queryKey: ["admin-posts"] });

  const create = useMutation({
    mutationFn: (status: string) =>
      api.admin.createPost({
        title, excerpt: excerpt || undefined, body,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean), status,
      }),
    onSuccess: () => { invalidate(); reset(); toast({ title: "Post saved", variant: "success" }); },
    onError: (e) => toast({ title: "Save failed", description: (e as Error).message, variant: "error" }),
  });

  const update = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<BlogPost> }) => api.admin.updatePost(id, data),
    onSuccess: () => { invalidate(); toast({ title: "Updated", variant: "success" }); },
  });
  const del = useMutation({
    mutationFn: (id: string) => api.admin.deletePost(id),
    onSuccess: () => { invalidate(); toast({ title: "Deleted", variant: "success" }); },
  });

  if (posts.isError) {
    const msg = (posts.error as Error)?.message || "";
    return (
      <div className="mx-auto max-w-md py-24 text-center">
        <h1 className="text-xl font-semibold">Operator access required</h1>
        <p className="mt-2 text-sm text-muted-foreground">{msg.includes("Operator") ? "SeQr Labs staff only." : msg}</p>
        <Link href="/dashboard" className="mt-4 inline-block text-sm underline">← Dashboard</Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Blog / CMS</h1>
        <Link href="/admin" className="text-sm text-muted-foreground underline">← Operator console</Link>
      </div>

      <Card className="mb-8">
        <CardHeader><CardTitle>New post</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Title</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="PQC is coming to Indian fintech" />
          </div>
          <div className="space-y-2">
            <Label>Excerpt (SEO summary)</Label>
            <Input value={excerpt} onChange={(e) => setExcerpt(e.target.value)} placeholder="Why SEBI CSCRF makes a CBOM urgent" />
          </div>
          <div className="space-y-2">
            <Label>Body (markdown)</Label>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={10}
              className="w-full rounded-md border bg-transparent p-3 font-mono text-sm"
              placeholder="# Heading\n\nYour post..."
            />
          </div>
          <div className="space-y-2">
            <Label>Tags (comma-separated)</Label>
            <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="pqc, india, sebi" />
          </div>
          <div className="flex gap-3">
            <Button variant="outline" disabled={!title || create.isPending} onClick={() => create.mutate("draft")}>
              Save draft
            </Button>
            <Button disabled={!title || create.isPending} onClick={() => create.mutate("published")}>
              Publish
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>All posts</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {(posts.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">No posts yet.</p>}
          {(posts.data ?? []).map((p: BlogPost) => (
            <div key={p.id} className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <div className="font-medium">{p.title}</div>
                <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                  <Badge variant={p.status === "published" ? "secondary" : "outline"}>{p.status}</Badge>
                  <span>/{p.slug}</span>
                </div>
              </div>
              <div className="flex gap-2">
                {p.status === "published" ? (
                  <Button size="sm" variant="outline" onClick={() => update.mutate({ id: p.id, data: { status: "draft" } })}>
                    Unpublish
                  </Button>
                ) : (
                  <Button size="sm" onClick={() => update.mutate({ id: p.id, data: { status: "published" } })}>
                    Publish
                  </Button>
                )}
                <Button size="sm" variant="destructive" onClick={() => del.mutate(p.id)}>Delete</Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
