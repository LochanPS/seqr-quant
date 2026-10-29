// Plain-language names and orderings shared across dashboard pages.

export const SEV_ORDER = ["immediate", "urgent", "planned"] as const;

const RULE_LABEL: Record<string, string> = {
  kex_must_be_hybrid: "Key exchange is not post-quantum hybrid",
  no_static_rsa_kex: "Static RSA key exchange, no forward secrecy",
  cert_min_rsa: "Certificate key below policy minimum",
  no_exposed_classical_origin: "Classical origin exposed behind the CDN edge",
};

export function ruleLabel(k: string) {
  return RULE_LABEL[k] ?? k.replace(/_/g, " ");
}

export function slotOf(rule: string) {
  if (rule.includes("kex")) return "tls:kex";
  if (rule.includes("cert")) return "tls:cert";
  return "origin";
}

const FRAMEWORK_LABEL: Record<string, string> = {
  PCI_DSS_12_3_3: "PCI DSS 12.3.3",
  SEBI_CSCRF: "SEBI CSCRF",
  RBI_QSAFE: "RBI Q-SAFE",
  RBI_Q_SAFE: "RBI Q-SAFE",
  DST_ROADMAP: "DST roadmap",
  DPDP_ACT: "DPDP Act",
  DPDP: "DPDP Act",
};

export function frameworkLabel(k: string) {
  return FRAMEWORK_LABEL[k] ?? k.replace(/_/g, " ");
}

/** Backend copy sometimes carries em dashes; render them as a comma-separated clause. */
export function plain(s: string | null | undefined): string {
  if (!s) return "";
  return s.replace(/\s*\u2014\s*/g, ", ").replace(/\s*\u2013\s*/g, " to ");
}

export const ASSET_TYPES = [
  { value: "domain", label: "Web / TLS", placeholder: "api.company.com" },
  { value: "ssh", label: "SSH", placeholder: "git.company.com" },
  { value: "smtp", label: "Mail (SMTP)", placeholder: "smtp.company.com" },
  { value: "postgres", label: "PostgreSQL", placeholder: "db.company.com" },
  { value: "mysql", label: "MySQL (TLS)", placeholder: "mysql.company.com" },
  { value: "mongodb", label: "MongoDB (TLS)", placeholder: "mongo.company.com" },
  { value: "amqp", label: "AMQP (RabbitMQ)", placeholder: "rabbit.company.com" },
  { value: "grpc", label: "gRPC (TLS)", placeholder: "grpc.company.com" },
] as const;

export const SENSITIVITIES = [
  { value: "internal", label: "Internal" },
  { value: "confidential", label: "Confidential" },
  { value: "regulated", label: "Regulated / PII" },
  { value: "secret", label: "Secret" },
] as const;

export function assetTypeLabel(t: string) {
  const found = ASSET_TYPES.find((a) => a.value === t);
  if (found) return found.label;
  return t.replace(/_/g, " ");
}

export const DEMO_TEMPLATES = ["banking", "healthcare", "telecom", "government", "saas"] as const;

export const ROLES = [
  { value: "admin", label: "Admin", note: "Full access, including team and security settings" },
  { value: "analyst", label: "Analyst", note: "Read and write assets, scans, plans" },
  { value: "auditor", label: "Auditor", note: "Read everything, plus the audit log" },
  { value: "viewer", label: "Viewer", note: "Read only" },
] as const;

export function roleRank(r: string) {
  return { admin: 3, analyst: 2, member: 2, auditor: 1, viewer: 0 }[r] ?? 0;
}

/** Turn a base64 string into a downloadable file. */
export function downloadBase64(b64: string, filename: string, type = "application/gzip") {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  downloadBlob(new Blob([bytes], { type }), filename);
}

export function downloadJson(data: unknown, filename: string) {
  downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }), filename);
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
