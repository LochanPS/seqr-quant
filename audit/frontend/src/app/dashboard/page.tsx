import { redirect } from "next/navigation";

// The crypto-asset graph (Posture) is the product's coherent home. The legacy scan-era
// overview read from a pipeline that is empty for graph-seeded orgs, so it is retired as the
// landing (its components remain in the repo for a future spine-backed rebuild).
export default function DashboardIndex() {
  redirect("/dashboard/posture");
}
