import { redirect } from "next/navigation";

// The crypto-asset graph overview (Posture) is the product home.
export default function DashboardIndex() {
  redirect("/dashboard/posture");
}
