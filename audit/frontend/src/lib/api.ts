import type {
  ApiKey,
  ApiKeyCreated,
  Asset,
  AuthResponse,
  CBOMParams,
  CBOMResponse,
  CBOMSummary,
  Component,
  ComplianceMap,
  CreateAsset,
  LoginData,
  Org,
  RegisterData,
  Report,
  RiskScore,
  Roadmap,
  Scan,
} from "./types";

const BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export const TOKEN_KEY = "seqr_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  if (typeof window !== "undefined") localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  if (typeof window !== "undefined") localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });

  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
    throw new Error("Unauthorized");
  }

  if (!res.ok) {
    let msg = await res.text();
    try {
      const parsed = JSON.parse(msg);
      msg = parsed.detail || msg;
    } catch {
      /* keep raw text */
    }
    throw new Error(msg || `Request failed (${res.status})`);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  auth: {
    register: (data: RegisterData) =>
      request<AuthResponse>("/auth/register", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    login: (data: LoginData) =>
      request<AuthResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    apiKeys: {
      list: () => request<ApiKey[]>("/auth/api-keys"),
      create: (name: string) =>
        request<ApiKeyCreated>("/auth/api-keys", {
          method: "POST",
          body: JSON.stringify({ name, scopes: [] }),
        }),
      revoke: (id: string) =>
        request<void>(`/auth/api-keys/${id}`, { method: "DELETE" }),
    },
  },
  org: {
    get: () => request<Org>("/org"),
    update: (data: { name?: string; sector?: string }) =>
      request<Org>("/org", { method: "PATCH", body: JSON.stringify(data) }),
  },
  assets: {
    list: () => request<Asset[]>("/assets"),
    get: (id: string) => request<Asset>(`/assets/${id}`),
    create: (data: CreateAsset) =>
      request<Asset>("/assets", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    scan: (id: string) =>
      request<{ scan_id: string; status: string }>(`/assets/${id}/scan`, {
        method: "POST",
      }),
    delete: (id: string) =>
      request<void>(`/assets/${id}`, { method: "DELETE" }),
  },
  scans: {
    list: () => request<Scan[]>("/scans"),
    get: (id: string) => request<Scan>(`/scans/${id}`),
  },
  cbom: {
    list: (params?: CBOMParams) =>
      request<CBOMResponse>(
        "/cbom" +
          (params
            ? "?" +
              new URLSearchParams(
                Object.fromEntries(
                  Object.entries(params).filter(([, v]) => v != null && v !== "")
                ) as Record<string, string>
              )
            : "")
      ),
    summary: () => request<CBOMSummary>("/cbom/summary"),
    patch: (id: string, migration_status: string) =>
      request<Component>(`/cbom/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ migration_status }),
      }),
    exportUrl: (format: string) => `${BASE}/cbom/export?format=${format}`,
  },
  risk: {
    score: () => request<RiskScore>("/risk/score"),
    compliance: () => request<ComplianceMap>("/risk/compliance"),
    roadmap: () => request<Roadmap>("/risk/roadmap"),
    hndl: () => request<Component[]>("/risk/hndl"),
  },
  reports: {
    list: () => request<Report[]>("/reports"),
    generate: (type: string) =>
      request<Report>("/reports/generate", {
        method: "POST",
        body: JSON.stringify({ type }),
      }),
    downloadUrl: (id: string) => `${BASE}/reports/${id}/download`,
  },
  graph: {
    assets: () => request<GraphAsset[]>("/graph/assets"),
    assetEdges: (id: string) => request<GraphEdge[]>(`/graph/assets/${id}/edges`),
    assetState: (id: string) => request<ComponentStateRow[]>(`/graph/assets/${id}/state`),
    componentStates: () => request<ComponentStateRow[]>("/graph/component-states"),
    evaluations: () => request<EvaluationRow[]>("/graph/evaluations"),
    currentViolations: () => request<ViolationRow[]>("/graph/violations/current"),
    attestations: () => request<AttestationRow[]>("/graph/attestations"),
    events: () => request<EventRow[]>("/graph/events"),
    generateAttestation: () =>
      request<{ attestation_id: string; artifact: unknown }>("/graph/attestations", {
        method: "POST",
      }),
    attestationDownloadUrl: (id: string) => `${BASE}/graph/attestations/${id}/download`,
    attestationCertUrl: (id: string) => `${BASE}/graph/attestations/${id}/certificate.pdf`,
  },
  remediation: {
    plan: (body: RemediationRequest) =>
      request<RemediationResult>("/remediation/plan", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  },
  migration: {
    pipeline: () => request<PipelineStatus>("/migration/pipeline"),
    dryRun: () => request<DryRun>("/migration/dry-run", { method: "POST" }),
    plans: () => request<PlanRow[]>("/migration/plans"),
    createPlan: () => request<PlanRow>("/migration/plans", { method: "POST" }),
    bundle: (planId: string) =>
      request<{ bundle_id: string; manifest: unknown; tar_base64: string }>(
        `/migration/plans/${planId}/bundle`,
        { method: "POST" }
      ),
    verify: (planId: string) =>
      request<VerifyReport>(`/migration/plans/${planId}/verify`, { method: "POST" }),
    reseed: (template: string) =>
      request<{ org_id: string; template: string }>(
        `/migration/demo/reseed?template=${encodeURIComponent(template)}`,
        { method: "POST" }
      ),
  },
  agent: {
    credentials: {
      list: () => request<AgentCredential[]>("/agent/credentials"),
      create: (name: string, expires_at?: string | null) =>
        request<AgentCredentialCreated>("/agent/credentials", {
          method: "POST",
          body: JSON.stringify({ name, expires_at: expires_at ?? null }),
        }),
      revoke: (id: string) =>
        request<void>(`/agent/credentials/${id}`, { method: "DELETE" }),
    },
    coverage: () => request<AgentCoverage>("/agent/coverage"),
  },
  admin: {
    orgs: () => request<AdminOrg[]>("/admin/orgs"),
    updateOrg: (id: string, data: { plan?: string; status?: string }) =>
      request<AdminOrg>(`/admin/orgs/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
    stats: () => request<PlatformStats>("/admin/stats"),
    posts: () => request<BlogPost[]>("/admin/posts"),
    createPost: (data: Partial<BlogPost>) =>
      request<BlogPost>("/admin/posts", { method: "POST", body: JSON.stringify(data) }),
    updatePost: (id: string, data: Partial<BlogPost>) =>
      request<BlogPost>(`/admin/posts/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
    deletePost: (id: string) =>
      request<void>(`/admin/posts/${id}`, { method: "DELETE" }),
  },
};

export interface AdminOrg {
  id: string;
  name: string;
  sector: string | null;
  plan: string;
  status: string;
  quantum_risk_score: number | null;
  user_count: number;
  asset_count: number;
  scan_count: number;
  last_scan_at: string | null;
  created_at: string;
}

export interface PlatformStats {
  total_orgs: number;
  total_users: number;
  total_assets: number;
  total_scans: number;
  orgs_by_plan: Record<string, number>;
  suspended_orgs: number;
}

export interface BlogPost {
  id: string;
  slug: string;
  title: string;
  excerpt: string | null;
  body: string;
  status: string;
  tags: string[];
  author_email: string | null;
  published_at: string | null;
  created_at: string;
}

// --- discovery-agent plane (PRD 15) -----------------------------------------
export interface AgentCredential {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  expires_at: string | null;
  created_at: string;
}
export interface AgentCredentialCreated extends AgentCredential {
  key: string; // raw sq_live_ key — shown exactly once
}
export interface AgentCoverage {
  agent: string | null;
  observations: number;
  assets_covered: number;
  plugin_coverage: string[];
  last_observed_at: string | null;
  last_event_at: string | null;
}

// --- platform spine + migration (PRD 13/14) ---------------------------------
export interface GraphAsset {
  id: string;
  type: string;
  name: string | null;
  identifier: string;
  provenance: string;
  status: string;
}
export interface GraphEdge {
  id: string;
  src_asset_id: string;
  dst_asset_id: string;
  relation: string;
  discovered_by: string;
  confidence: number;
  valid_from: string;
  valid_to: string | null;
}
export interface ComponentStateRow {
  id: string;
  asset_id: string;
  slot_key: string;
  winning_observation_id: string;
  latest_policy_evaluation_id: string | null;
  conflict: boolean;
  algorithm: string | null;
  algorithm_family: string | null;
  quantum_status: string | null;
  source: string | null;
}
export interface EvaluationRow {
  id: string;
  policy_id: string;
  policy_content_hash: string;
  result_hash: string;
  violations_count: number;
  covered_asset_set: string[] | null;
  ran_at: string;
}
export interface ViolationRow {
  id: string;
  evaluation_id: string;
  asset_id: string;
  rule_key: string;
  severity: string;
  actual: string | null;
  target_state: string | null;
}
export interface AttestationRow {
  id: string;
  policy_version: string;
  policy_content_hash: string;
  evaluation_id: string;
  evaluation_result_hash: string;
  graph_schema_version: number;
  key_id: string;
  signature: string;
  created_at: string;
}
export interface EventRow {
  id: string;
  type: string;
  actor: string | null;
  asset_id: string | null;
  payload: Record<string, unknown> | null;
  at: string;
}
export interface PipelineStatus {
  org_id: string;
  assets: { total: number; by_provenance: Record<string, number> };
  edges: number;
  component_states: { total: number; conflicts: number };
  latest_evaluation: { id: string; ran_at: string | null; result_hash: string; violations_count: number } | null;
  open_violations: number;
  plans: { total: number; by_status: Record<string, number> };
  bundles: number;
  attestations: number;
  converged: boolean;
  recent_events: { type: string; at: string | null }[];
}
export interface DryRun {
  evaluation_id: string;
  change_count: number;
  by_platform: Record<string, number>;
  affected_assets: string[];
  changes: {
    asset_id: string;
    rule_key: string;
    provider: string;
    action: string;
    slot: string | null;
    from: string | null;
    to: string | null;
    snippets: string[];
    validation: string[];
    rollback: string[];
    manual: boolean;
  }[];
  persisted: boolean;
}
export interface PlanRow {
  id: string;
  policy_evaluation_id: string;
  status: string;
}
export interface VerifyReport {
  plan_id: string;
  new_evaluation_id: string;
  converged: boolean;
  cleared: string[];
  remaining: string[];
}

export { BASE as API_BASE };

// ── Remediation planner (risk v2 + QpiAI Opt) ────────────────────────────────

export interface RemediationRequest {
  report?: Record<string, unknown> | null;
  budget: number;
  use_opt: boolean;
  use_qaoa: boolean;
  curve?: number[];
}

export interface RemediationPlan {
  method: string;
  chosen: string[];
  effort: number;
  budget: number;
  residual: number;
  removed_pct: number;
  feasible: boolean;
  solver_time_s: number | null;
  detail: string;
}

export interface RemediationAlternative {
  chosen: string[];
  probability: number;
  effort: number;
  residual: number;
  feasible: boolean;
}

export interface RemediationResult {
  source: string;
  baseline_risk: number;
  budget: number;
  actions: { id: string; label: string; effort: number; covers: number }[];
  findings: {
    rel_path: string;
    line_number: number;
    algorithm: string;
    score: number;
    tier: string;
    role: string;
    exposure: string;
    hndl: boolean;
    effort_hours: number;
    top_reason: string;
  }[];
  plans: { greedy?: RemediationPlan; exhaustive?: RemediationPlan | null; opt?: RemediationPlan };
  errors: Record<string, string>;
  curve: { budget: number; removed_pct: number; chosen: string[]; method: string }[];
  qaoa?: {
    qubits: number;
    reduced_actions: string[];
    reps: number;
    cvar_alpha: number;
    seconds: number;
    alternatives: RemediationAlternative[];
    p_optimal: number;
    p_uniform: number;
    amplification: number | null;
  };
  opt_gap_to_optimum?: number;
  notes: string[];
}
