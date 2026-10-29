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
  User,
} from "./types";

const BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export const TOKEN_KEY = "seqr_token";
export const REFRESH_KEY = "seqr_refresh";

/** An HTTP failure carrying the status, so callers can tell 403/404 from real errors. */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export function isStatus(err: unknown, ...codes: number[]): boolean {
  return err instanceof ApiError && codes.includes(err.status);
}

function store(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return store()?.getItem(TOKEN_KEY) ?? null;
}

export function getRefreshToken(): string | null {
  return store()?.getItem(REFRESH_KEY) ?? null;
}

export function setToken(token: string, refresh?: string | null) {
  const s = store();
  if (!s) return;
  s.setItem(TOKEN_KEY, token);
  if (refresh) s.setItem(REFRESH_KEY, refresh);
}

export function clearToken() {
  const s = store();
  if (!s) return;
  s.removeItem(TOKEN_KEY);
  s.removeItem(REFRESH_KEY);
}

function redirectToLogin() {
  if (typeof window === "undefined") return;
  const path = window.location.pathname;
  if (path.startsWith("/login") || path.startsWith("/register")) return;
  const next = encodeURIComponent(path + window.location.search);
  window.location.href = `/login?next=${next}`;
}

// One refresh in flight at a time; concurrent 401s wait on the same promise.
let refreshing: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  const rt = getRefreshToken();
  if (!rt) return false;
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const res = await fetch(`${BASE}/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: rt }),
        });
        if (!res.ok) return false;
        const data = (await res.json()) as { access_token?: string };
        if (!data.access_token) return false;
        setToken(data.access_token);
        return true;
      } catch {
        return false;
      } finally {
        setTimeout(() => {
          refreshing = null;
        }, 0);
      }
    })();
  }
  return refreshing;
}

async function readError(res: Response): Promise<string> {
  let msg = await res.text();
  try {
    const parsed = JSON.parse(msg);
    const d = parsed.detail ?? parsed.message ?? parsed.error;
    if (typeof d === "string") msg = d;
    else if (Array.isArray(d)) msg = d.map((x) => x?.msg ?? String(x)).join("; ");
    else if (d) msg = JSON.stringify(d);
  } catch {
    /* keep raw text */
  }
  return msg || `Request failed (${res.status})`;
}

async function request<T>(path: string, options: RequestInit = {}, retried = false): Promise<T> {
  const token = getToken();
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
      },
    });
  } catch {
    throw new ApiError("Cannot reach the SeQr API. Check that the backend is running.", 0);
  }

  if (res.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/auth/mfa/login")) {
    if (!retried && (await tryRefresh())) return request<T>(path, options, true);
    clearToken();
    redirectToLogin();
    throw new ApiError("Your session has ended. Sign in again.", 401);
  }

  if (!res.ok) throw new ApiError(await readError(res), res.status);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

const qs = (params: Record<string, string | number | null | undefined>) => {
  const entries = Object.entries(params).filter(([, v]) => v != null && v !== "");
  if (!entries.length) return "";
  return "?" + new URLSearchParams(entries.map(([k, v]) => [k, String(v)])).toString();
};

export const api = {
  auth: {
    register: (data: RegisterData) =>
      request<AuthResponse>("/auth/register", { method: "POST", body: JSON.stringify(data) }),
    login: (data: LoginData) =>
      request<AuthResponse>("/auth/login", { method: "POST", body: JSON.stringify(data) }),
    mfaLogin: (temp_token: string, totp_code: string) =>
      request<AuthResponse>("/auth/mfa/login", {
        method: "POST",
        body: JSON.stringify({ temp_token, totp_code }),
      }),
    mfaSetup: () => request<{ secret: string; qr_code: string; uri: string }>("/auth/mfa/setup", { method: "POST" }),
    mfaVerify: (totp_code: string) =>
      request<{ mfa_enabled: boolean }>("/auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ totp_code }),
      }),
    logout: () => request<{ status: string }>("/auth/logout", { method: "POST" }),
    apiKeys: {
      list: () => request<ApiKey[]>("/auth/api-keys"),
      create: (name: string) =>
        request<ApiKeyCreated>("/auth/api-keys", {
          method: "POST",
          body: JSON.stringify({ name, scopes: [] }),
        }),
      revoke: (id: string) => request<void>(`/auth/api-keys/${id}`, { method: "DELETE" }),
    },
  },
  org: {
    get: () => request<Org>("/org"),
    update: (data: { name?: string; sector?: string }) =>
      request<Org>("/org", { method: "PATCH", body: JSON.stringify(data) }),
    users: () => request<User[]>("/org/users"),
    invite: (email: string, role: string) =>
      request<InviteResult>("/org/users/invite", {
        method: "POST",
        body: JSON.stringify({ email, role }),
      }),
    setRole: (userId: string, role: string) =>
      request<User>(`/org/users/${userId}/role`, { method: "PATCH", body: JSON.stringify({ role }) }),
  },
  assets: {
    list: () => request<Asset[]>("/assets"),
    get: (id: string) => request<Asset>(`/assets/${id}`),
    create: (data: CreateAsset) =>
      request<Asset>("/assets", { method: "POST", body: JSON.stringify(data) }),
    scan: (id: string) =>
      request<{ scan_id: string; status: string }>(`/assets/${id}/scan`, { method: "POST" }),
    scanAll: () =>
      request<{ queued: number; scans: { scan_id?: string; asset_id?: string }[] }>("/assets/scan-all", {
        method: "POST",
      }),
    delete: (id: string) => request<void>(`/assets/${id}`, { method: "DELETE" }),
  },
  scans: {
    list: () => request<Scan[]>("/scans"),
    get: (id: string) => request<Scan>(`/scans/${id}`),
  },
  cbom: {
    list: (params?: CBOMParams & { location?: string }) =>
      request<CBOMResponse>("/cbom" + qs((params ?? {}) as Record<string, string>)),
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
      request<Report>("/reports/generate", { method: "POST", body: JSON.stringify({ type }) }),
    downloadUrl: (id: string) => `${BASE}/reports/${id}/download`,
  },
  ci: {
    list: () => request<CIReport[]>("/ci/reports"),
    get: (id: string) => request<CIReportDetail>(`/ci/reports/${id}`),
  },
  audit: {
    list: (params: { actor?: string; action?: string; since?: string; until?: string; limit?: number; offset?: number }) =>
      request<AuditEvent[]>("/audit" + qs(params)),
  },
  sso: {
    get: () => request<OIDCConfig>("/sso/config"),
    put: (data: OIDCConfigIn) => request<OIDCConfig>("/sso/config", { method: "PUT", body: JSON.stringify(data) }),
    remove: () => request<void>("/sso/config", { method: "DELETE" }),
  },
  saml: {
    get: () => request<SAMLConfig>("/saml/config"),
    put: (data: SAMLConfigIn) => request<SAMLConfig>("/saml/config", { method: "PUT", body: JSON.stringify(data) }),
    remove: () => request<void>("/saml/config", { method: "DELETE" }),
    metadataUrl: (providerId?: string | null) => `${BASE}/saml/metadata${providerId ? `?provider_id=${providerId}` : ""}`,
  },
  graph: {
    assets: () => request<GraphAsset[]>("/graph/assets"),
    asset: (id: string) => request<GraphAsset>(`/graph/assets/${id}`),
    assetEdges: (id: string) => request<GraphEdge[]>(`/graph/assets/${id}/edges`),
    assetState: (id: string) => request<ComponentStateRow[]>(`/graph/assets/${id}/state`),
    componentStates: () => request<ComponentStateRow[]>("/graph/component-states"),
    contextRisk: () => request<ContextRiskResult>("/graph/risk"),
    evaluations: () => request<EvaluationRow[]>("/graph/evaluations"),
    currentViolations: () => request<ViolationRow[]>("/graph/violations/current"),
    attestations: () => request<AttestationRow[]>("/graph/attestations"),
    events: () => request<EventRow[]>("/graph/events"),
    generateAttestation: () =>
      request<{ attestation_id: string; artifact: unknown }>("/graph/attestations", { method: "POST" }),
    attestationDownloadUrl: (id: string) => `${BASE}/graph/attestations/${id}/download`,
    attestationCertUrl: (id: string) => `${BASE}/graph/attestations/${id}/certificate.pdf`,
  },
  remediation: {
    plan: (body: RemediationRequest) =>
      request<RemediationResult>("/remediation/plan", { method: "POST", body: JSON.stringify(body) }),
    planInfra: (body: Omit<RemediationRequest, "report">) =>
      request<RemediationResult>("/remediation/plan-infra", { method: "POST", body: JSON.stringify(body) }),
    qpiaiDevices: () =>
      request<{ devices: QCloudDeviceStatus[]; error: string | null }>("/remediation/qpiai/devices"),
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
      revoke: (id: string) => request<void>(`/agent/credentials/${id}`, { method: "DELETE" }),
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
    deletePost: (id: string) => request<void>(`/admin/posts/${id}`, { method: "DELETE" }),
  },
};

export interface InviteResult {
  email: string;
  role: string;
  temporary_password: string;
  must_change_password: boolean;
}

export interface CIReport {
  id: string;
  repo: string;
  pr_number: number | null;
  commit_sha: string | null;
  branch: string | null;
  source: string;
  findings_count: number;
  summary: Record<string, unknown> | null;
  created_at: string;
}
export interface CIReportDetail extends CIReport {
  findings: Record<string, unknown>[];
}

export interface AuditEvent {
  id: string;
  org_id: string | null;
  actor: string | null;
  actor_type: string;
  action: string;
  method: string | null;
  path: string | null;
  status_code: number | null;
  target: string | null;
  ip: string | null;
  detail: unknown;
  at: string;
}

export interface OIDCConfigIn {
  issuer: string;
  client_id: string;
  client_secret?: string | null;
  display_name: string;
  discovery_url?: string | null;
  scopes: string;
  groups_claim: string;
  group_role_map: Record<string, string>;
  default_role: string;
  email_domain?: string | null;
  auto_provision: boolean;
  enabled: boolean;
}
export interface OIDCConfig extends Partial<Omit<OIDCConfigIn, "client_secret">> {
  configured: boolean;
  id: string | null;
  has_client_secret: boolean;
  redirect_uri: string | null;
  login_url: string | null;
}

export interface SAMLConfigIn {
  idp_entity_id: string;
  idp_sso_url: string;
  idp_x509_cert: string;
  idp_slo_url?: string | null;
  sp_entity_id?: string | null;
  display_name: string;
  want_assertions_signed: boolean;
  name_id_format?: string | null;
  email_attribute?: string | null;
  groups_attribute: string;
  group_role_map: Record<string, string>;
  default_role: string;
  email_domain?: string | null;
  auto_provision: boolean;
  enabled: boolean;
}
export interface SAMLConfig extends Partial<SAMLConfigIn> {
  configured: boolean;
  id: string | null;
  acs_url?: string | null;
  metadata_url?: string | null;
  login_url?: string | null;
}

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

// Discovery-agent plane (PRD 15)
export interface AgentCredential {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  expires_at: string | null;
  created_at: string;
}
export interface AgentCredentialCreated extends AgentCredential {
  key: string; // raw sq_live_ key, shown exactly once
}
export interface AgentCoverage {
  agent: string | null;
  observations: number;
  assets_covered: number;
  plugin_coverage: string[];
  last_observed_at: string | null;
  last_event_at: string | null;
}

// Platform spine + migration (PRD 13/14)
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

// Remediation planner (risk v2 + QpiAI Opt)

export interface RemediationRequest {
  report?: Record<string, unknown> | null;
  budget: number;
  use_opt: boolean;
  use_qaoa: boolean;
  curve?: number[];
  qaoa_device?: QCloudDevice | null;
  qaoa_warm_start?: boolean;
  opt_platform?: boolean;
}

export type QCloudDevice =
  | "QpiAI-QSV-Simulator"
  | "QpiAI-QDM-Simulator"
  | "QpiAI-QTN-Simulator"
  | "QpiAI-QSV-Lite"
  | "QpiAI-QDM-Lite"
  | "QpiAI-Indus-1";

export interface QCloudDeviceStatus {
  device: string;
  status: string;
  usage_rate: number | null;
  method: string | null;
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
    slot_key?: string | null;
    asset_type?: string | null;
  }[];
  plans: {
    greedy?: RemediationPlan;
    exhaustive?: RemediationPlan | null;
    opt?: RemediationPlan;
    opt_platform?: RemediationPlan;
  };
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
    reduced_optimum: number;
    sampled_optimum: boolean;
    contains_best_known: boolean;
    backend: string;
    warm_start: boolean;
    p_optimal_warm_state?: number;
    cloud?: {
      device: string;
      experiment: string;
      shots: number;
      status: "ok" | "failed";
      job_ids: string[];
      error?: string;
      seconds: number;
    };
  };
  opt_gap_to_optimum?: number;
  notes: string[];
}

// Context-aware risk (risk engine v2) over infrastructure slots

export interface ContextRiskComponent {
  asset_id: string | null;
  asset_type: string | null;
  slot_key: string | null;
  file_path: string;
  rel_path: string;
  algorithm: string;
  score: number;
  tier: string;
  role: string;
  exposure: string;
  data_sensitivity: string;
  shelf_life: string;
  dependents: number;
  hndl: boolean;
  inferred: string[];
  reasons: string[];
  source: string | null;
}

export interface ContextRiskResult {
  summary: {
    findings: number;
    tiers: Record<string, number>;
    hndl: number;
    hndl_disclaimer: string;
  };
  components: ContextRiskComponent[];
}
