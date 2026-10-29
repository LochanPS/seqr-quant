"use client";

import * as D from "@radix-ui/react-dialog";
import { cn } from "@/lib/utils";
import { IconClose } from "@/components/icons";

export const Dialog = D.Root;
export const DialogTrigger = D.Trigger;
export const DialogClose = D.Close;

export function DialogContent({
  title,
  description,
  children,
  className,
  wide,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  wide?: boolean;
}) {
  return (
    <D.Portal>
      <D.Overlay className="overlay fixed inset-0 z-50 bg-bg/60" />
      <D.Content
        {...(description ? {} : { "aria-describedby": undefined })}
        className={cn(
          "dialog-panel fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 max-h-[calc(100dvh-2rem)] w-[calc(100vw-2rem)] overflow-y-auto border border-ink bg-bg",
          wide ? "max-w-3xl" : "max-w-lg",
          className
        )}
      >
        <div className="flex items-start justify-between gap-4 border-b border-rule px-6 py-5">
          <div>
            <D.Title className="font-display text-xl text-ink">{title}</D.Title>
            {description && <D.Description className="mt-1 text-sm text-ink-2">{description}</D.Description>}
          </div>
          <D.Close
            aria-label="Close dialog"
            className="-mr-2 -mt-1 inline-flex h-8 w-8 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-ink"
          >
            <IconClose size={18} />
          </D.Close>
        </div>
        <div className="px-6 py-5">{children}</div>
      </D.Content>
    </D.Portal>
  );
}

export function DialogFooter({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("-mx-6 -mb-5 mt-6 flex flex-wrap items-center justify-end gap-2 border-t border-rule px-6 py-4", className)}>
      {children}
    </div>
  );
}

/** Side sheet: slides from an edge on the press ease. */
export function SheetContent({
  side = "right",
  title,
  children,
  className,
}: {
  side?: "right" | "left";
  title: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <D.Portal>
      <D.Overlay className="overlay fixed inset-0 z-50 bg-bg/60" />
      <D.Content
        aria-describedby={undefined}
        className={cn(
          "fixed inset-y-0 z-50 flex w-[min(420px,100vw)] flex-col bg-bg",
          side === "right" ? "sheet-right right-0 border-l border-ink" : "sheet-left left-0 border-r border-ink",
          className
        )}
      >
        <div className="flex h-16 shrink-0 items-center justify-between border-b border-rule px-5">
          <D.Title className="eyebrow text-ink">{title}</D.Title>
          <D.Close
            aria-label="Close panel"
            className="inline-flex h-8 w-8 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-ink"
          >
            <IconClose size={18} />
          </D.Close>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </D.Content>
    </D.Portal>
  );
}
