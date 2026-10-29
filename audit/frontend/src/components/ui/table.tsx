"use client";

import { cn } from "@/lib/utils";
import { IconSortAsc, IconSortDesc } from "@/components/icons";

// Tables are set like a printed ledger: hairline rows, mono heads, no zebra fill.
// On narrow screens rows stack: each <Td label="..."> shows its label inline.

export function Table({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full border-collapse text-sm", className)}>{children}</table>
    </div>
  );
}

export function THead({ children }: { children: React.ReactNode }) {
  return <thead className="hidden border-b border-ink md:table-header-group">{children}</thead>;
}

export function TBody({ children, className }: { children: React.ReactNode; className?: string }) {
  return <tbody className={className}>{children}</tbody>;
}

export function Tr({
  children,
  className,
  onClick,
  ...rest
}: React.HTMLAttributes<HTMLTableRowElement> & { children: React.ReactNode }) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        "grid grid-cols-1 gap-1 border-b border-rule py-3 md:table-row md:py-0",
        onClick && "cursor-pointer transition-colors duration-micro hover:bg-surface",
        className
      )}
      {...rest}
    >
      {children}
    </tr>
  );
}

export function Th({
  children,
  className,
  align = "left",
  sort,
  onSort,
}: {
  children?: React.ReactNode;
  className?: string;
  align?: "left" | "right";
  sort?: "asc" | "desc" | null;
  onSort?: () => void;
}) {
  const inner = (
    <span className={cn("inline-flex items-center gap-1", align === "right" && "flex-row-reverse")}>
      {children}
      {onSort && (sort === "asc" ? <IconSortAsc size={14} /> : sort === "desc" ? <IconSortDesc size={14} /> : null)}
    </span>
  );
  return (
    <th
      scope="col"
      aria-sort={sort === "asc" ? "ascending" : sort === "desc" ? "descending" : undefined}
      className={cn("eyebrow whitespace-nowrap px-3 py-2.5 font-normal", align === "right" ? "text-right" : "text-left", className)}
    >
      {onSort ? (
        <button onClick={onSort} className="uppercase transition-colors duration-micro hover:text-ink">
          {inner}
        </button>
      ) : (
        inner
      )}
    </th>
  );
}

export function Td({
  children,
  className,
  label,
  align = "left",
  mono,
  colSpan,
}: {
  children?: React.ReactNode;
  className?: string;
  label?: string;
  align?: "left" | "right";
  mono?: boolean;
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={cn(
        "flex items-baseline justify-between gap-4 px-0 align-middle md:table-cell md:px-3 md:py-3",
        align === "right" && "md:text-right",
        mono && "font-mono text-[13px] tabular",
        className
      )}
    >
      {label && <span className="eyebrow shrink-0 md:hidden">{label}</span>}
      <span className={cn("min-w-0 text-right", align === "left" && "md:text-left")}>{children}</span>
    </td>
  );
}

/** Generic sort state helper for client-side tables. */
export function nextSort<K extends string>(
  current: { key: K; dir: "asc" | "desc" } | null,
  key: K
): { key: K; dir: "asc" | "desc" } | null {
  if (!current || current.key !== key) return { key, dir: "asc" };
  if (current.dir === "asc") return { key, dir: "desc" };
  return null;
}

export function sortRows<T>(rows: T[], sort: { key: string; dir: "asc" | "desc" } | null, get: (r: T, k: string) => unknown) {
  if (!sort) return rows;
  const out = [...rows].sort((a, b) => {
    const x = get(a, sort.key);
    const y = get(b, sort.key);
    if (x == null && y == null) return 0;
    if (x == null) return 1;
    if (y == null) return -1;
    if (typeof x === "number" && typeof y === "number") return x - y;
    return String(x).localeCompare(String(y), undefined, { numeric: true });
  });
  return sort.dir === "desc" ? out.reverse() : out;
}
