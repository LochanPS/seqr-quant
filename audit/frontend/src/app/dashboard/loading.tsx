import { ReadoutSkeleton, Skeleton, TableSkeleton } from "@/components/ui/feedback";

export default function Loading() {
  return (
    <div className="space-y-10" role="status" aria-label="Loading page">
      <div className="space-y-4 border-b border-ink pb-6">
        <Skeleton className="h-2.5 w-24" />
        <Skeleton className="h-11 w-96 max-w-full" />
        <Skeleton className="h-3 w-[32rem] max-w-full" />
      </div>
      <ReadoutSkeleton />
      <TableSkeleton />
    </div>
  );
}
