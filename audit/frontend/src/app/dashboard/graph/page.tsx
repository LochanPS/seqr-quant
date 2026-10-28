import { CryptoGraphExplorer } from "@/components/graph/CryptoGraphExplorer";

export default function GraphPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Crypto-Asset Graph</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Explore your cryptographic estate — assets, their component state, policy violations,
          and how they connect. Read-only view over the live graph.
        </p>
      </div>
      <CryptoGraphExplorer />
    </div>
  );
}
