import { cn } from "@/lib/utils";

export function LogoMark({ className }: { className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src="/logo.png"
      alt="SeQr Labs"
      className={cn("h-7 w-7 rounded-md object-contain", className)}
    />
  );
}

export function Logo({
  collapsed = false,
  className,
}: {
  collapsed?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <LogoMark />
      {!collapsed && (
        <span className="text-lg font-semibold tracking-tight text-white">
          SeQr<span> Labs</span>
        </span>
      )}
    </div>
  );
}
