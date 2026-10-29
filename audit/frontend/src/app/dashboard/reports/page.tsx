"use client";

import Link from "next/link";
import { Suspense, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, isStatus } from "@/lib/api";
import { errMsg, humanize, shortId } from "@/lib/utils";
import { openWithAuth } from "@/lib/download";
import { PageHeader, RelTime } from "@/components/ui/page";
import { Tabs, TabsContent, TabsList } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Dialog, SheetContent } from "@/components/ui/dialog";
import { BlockSkeleton, EmptyState, ErrorState, Notice, TableSkeleton } from "@/components/ui/feedback";
import { Chip, StatusChip } from "@/components/ui/marks";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { CodeBlock } from "@/components/ui/code";
import { useToast } from "@/components/ui/toast";
import { IconDownload, IconReports } from "@/components/icons";

const TYPES = [
  {
    type: "executive_summary",
    title: "Executive summary",
    body: "Two pages for the board: overall quantum risk, compliance standing against PCI DSS and SEBI CSCRF, and the top migration priorities.",
    pages: "2 pages",
  },
  {
    type: "technical_audit",
    title: "Technical audit",
    body: "The full record for engineers and auditors: every component, its location, threat timeline and the recommended post-quantum replacement.",
    pages: "Full inventory",
  },
];

function ReportsInner() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const tab = params.get("tab") === "ci" ? "ci" : "pdf";
  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="Evidence"
        title="Reports"
        description="Signed-off documents for auditors and boards, generated from your latest scans, plus findings pushed from CI."
      />
      <Tabs value={tab} onValueChange={(v) => router.replace(v === "ci" ? `${pathname}?tab=ci` : pathname, { scroll: false })}>
        <TabsList
          value={tab}
          items={[
            { value: "pdf", label: "PDF reports" },
            { value: "ci", label: "CI findings" },
          ]}
        />
        <TabsContent value="pdf">
          <PdfReports />
        </TabsContent>
        <TabsContent value="ci">
          <CiReports />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function PdfReports() {
  const qc = useQueryClient();
  const toast = useToast();
  const reports = useQuery({ queryKey: ["reports"], queryFn: api.reports.list });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans.list });
  const gen = useMutation({
    mutationFn: (type: string) => api.reports.generate(type),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["reports"] });
      toast({
        title: r.status === "failed" ? "Report generation failed" : "Report generated",
        description: r.status === "failed" ? r.error_message ?? undefined : `${humanize(r.type)} is ready to download.`,
        tone: r.status === "failed" ? "error" : "success",
      });
    },
    onError: (e) => toast({ title: "Generation failed", description: errMsg(e), tone: "error" }),
  });
  const [opening, setOpening] = useState<string | null>(null);
  const download = async (id: string) => {
    setOpening(id);
    try {
      await openWithAuth(api.reports.downloadUrl(id));
    } catch (e) {
      toast({ title: "Download failed", description: errMsg(e), tone: "error" });
    } finally {
      setOpening(null);
    }
  };
  const hasFindings = (scans.data ?? []).some((s) => s.components_found > 0);

  return (
    <div className="space-y-12">
      {!scans.isLoading && !hasFindings && (
        <Notice title="Reports read scan results">
          No scan has recorded components yet, so a report would be empty.{" "}
          <Link href="/dashboard/assets" className="text-ink link-underline">
            Run a scan to generate a report
          </Link>
          .
        </Notice>
      )}
      <div className="grid gap-px border-y border-ink bg-rule md:grid-cols-2">
        {TYPES.map((t) => (
          <article key={t.type} className="flex flex-col gap-4 bg-bg p-7">
            <div className="flex items-center justify-between">
              <IconReports size={22} className="text-ink-3" />
              <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">{t.pages} · PDF</span>
            </div>
            <h2 className="font-display text-2xl text-ink">{t.title}</h2>
            <p className="max-w-md text-sm leading-relaxed text-ink-2">{t.body}</p>
            <div className="mt-auto pt-2">
              <Button onClick={() => gen.mutate(t.type)} pending={gen.isPending && gen.variables === t.type} pendingLabel="Generating" disabled={gen.isPending}>
                Generate
              </Button>
            </div>
          </article>
        ))}
      </div>

      <section>
        <h2 className="mb-4 font-display text-[1.45rem] text-ink">Generated reports</h2>
        {reports.isLoading ? (
          <TableSkeleton cols={5} rows={3} />
        ) : reports.isError ? (
          <ErrorState message={errMsg(reports.error)} onRetry={() => reports.refetch()} />
        ) : !reports.data?.length ? (
          <EmptyState title="No reports yet" body="Generate one above. Each report is kept here for download." />
        ) : (
          <Table>
            <THead>
              <tr>
                <Th>Type</Th>
                <Th>Generated</Th>
                <Th align="right">Components</Th>
                <Th align="right">Risk at time</Th>
                <Th>Status</Th>
                <Th align="right">
                  <span className="sr-only">Download</span>
                </Th>
              </tr>
            </THead>
            <TBody>
              {reports.data.map((r) => (
                <Tr key={r.id}>
                  <Td label="Type">{humanize(r.type)}</Td>
                  <Td label="Generated" className="text-ink-2">
                    <RelTime value={r.generated_at ?? r.created_at} />
                  </Td>
                  <Td label="Components" align="right" mono>
                    {r.component_count ?? "n/a"}
                  </Td>
                  <Td label="Risk" align="right" mono>
                    {r.risk_score_at_generation ?? "n/a"}
                  </Td>
                  <Td label="Status">
                    <StatusChip value={r.status} />
                  </Td>
                  <Td align="right">
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={r.status !== "complete" && r.status !== "completed" && r.status !== "ready"}
                      pending={opening === r.id}
                      pendingLabel="Opening"
                      onClick={() => download(r.id)}
                    >
                      <IconDownload size={14} /> Download
                    </Button>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </section>
    </div>
  );
}

function CiReports() {
  const list = useQuery({ queryKey: ["ci-reports"], queryFn: api.ci.list, retry: false });
  const [openId, setOpenId] = useState<string | null>(null);
  const detail = useQuery({ queryKey: ["ci-report", openId], queryFn: () => api.ci.get(openId!), enabled: !!openId, retry: false });

  if (list.isLoading) return <TableSkeleton cols={5} rows={3} />;
  if (list.isError)
    return isStatus(list.error, 403, 404) ? (
      <Notice title="CI ingest is turned off for this deployment">An administrator can enable it with CI_INGEST_ENABLED. Until then, seqr ci runs locally and reports in the pull request only.</Notice>
    ) : (
      <ErrorState message={errMsg(list.error)} onRetry={() => list.refetch()} />
    );
  if (!list.data?.length)
    return (
      <div className="space-y-6">
        <EmptyState title="No CI findings yet" body="Push findings from your pipeline with the CLI. Each pull request appears here with its findings." />
        <CodeBlock filename="ci step" code={`seqr ci --changed-only --fail-on urgent --push`} />
      </div>
    );

  return (
    <>
      <Table>
        <THead>
          <tr>
            <Th>Repository</Th>
            <Th>Pull request</Th>
            <Th>Branch</Th>
            <Th align="right">Findings</Th>
            <Th>Received</Th>
          </tr>
        </THead>
        <TBody>
          {list.data.map((r) => (
            <Tr key={r.id} onClick={() => setOpenId(r.id)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setOpenId(r.id)}>
              <Td label="Repository" mono>
                {r.repo}
              </Td>
              <Td label="PR" mono>
                {r.pr_number ? `#${r.pr_number}` : "n/a"} {r.commit_sha && <span className="text-ink-3">{r.commit_sha.slice(0, 7)}</span>}
              </Td>
              <Td label="Branch" mono className="text-ink-2">
                {r.branch ?? "n/a"}
              </Td>
              <Td label="Findings" align="right" mono className={r.findings_count ? "text-immediate" : undefined}>
                {r.findings_count}
              </Td>
              <Td label="Received" className="text-ink-2">
                <RelTime value={r.created_at} />
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
      <Dialog open={!!openId} onOpenChange={(o) => !o && setOpenId(null)}>
        <SheetContent title={detail.data ? `${detail.data.repo} ${detail.data.pr_number ? `#${detail.data.pr_number}` : ""}` : "CI report"}>
          <div className="space-y-5 p-5">
            {detail.isLoading ? (
              <BlockSkeleton lines={8} />
            ) : detail.isError ? (
              <ErrorState message={errMsg(detail.error)} onRetry={() => detail.refetch()} />
            ) : detail.data ? (
              <>
                <div className="flex flex-wrap gap-2">
                  <Chip>{detail.data.source}</Chip>
                  <Chip tone={detail.data.findings_count ? "immediate" : "safe"}>{detail.data.findings_count} findings</Chip>
                  {detail.data.commit_sha && <Chip>{shortId(detail.data.commit_sha, 7)}</Chip>}
                </div>
                <ul className="border-t border-rule">
                  {detail.data.findings.map((f, i) => (
                    <li key={i} className="border-b border-rule py-3">
                      <p className="font-mono text-sm text-ink">{String(f.algorithm ?? f.rule ?? "finding")}</p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-ink-3">
                        {String(f.file ?? f.path ?? f.location ?? "")}
                        {f.line ? `:${f.line}` : ""}
                      </p>
                      {f.severity ? <StatusChip value={String(f.severity)} className="mt-2" /> : null}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        </SheetContent>
      </Dialog>
    </>
  );
}

export default function ReportsPage() {
  return (
    <Suspense fallback={<TableSkeleton />}>
      <ReportsInner />
    </Suspense>
  );
}
