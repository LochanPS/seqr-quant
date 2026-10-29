// ── Auth / Org / User ────────────────────────────────────────────────────────
export interface RegisterData {
  name: string;
  email: string;
  org_name: string;
  password: string;
}

export interface LoginData {
  email: string;
  password: string;
}

export interface User {
  id: string;
  email: string;
  name: string | null;
  role: string;
  mfa_enabled: boolean;
  created_at: string;
}

export interface Org {
  id: string;
  name: string;
  domain: string | null;
  sector: string | null;
  plan: string;
  quantum_risk_score: number | null;
  created_at: string;
  license_expires_at?: string | null;
  viewer_is_operator?: boolean;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user?: User;
  org?: Org;
  mfa_required?: boolean;
  temp_token?: string;
}

// ── Assets ───────────────────────────────────────────────────────────────────
export interface Asset {
  id: string;
  org_id: string;
  type: string;
  name: string | null;
  identifier: string;
  data_sensitivity: string;
  status: string;
  scan_schedule: string;
  last_scanned_at: string | null;
  created_at: string;
  updated_at: string;
  last_scan_id?: string | null;
  last_scan_status?: string | null;
}

export interface CreateAsset {
  type: string;
  name?: string;
  identifier: string;
  data_sensitivity: string;
}

// ── Scans ────────────────────────────────────────────────────────────────────
export interface Scan {
  id: string;
  org_id: string;
  asset_id: string | null;
  type: string;
  status: string;
  trigger: string;
  celery_task_id: string | null;
  components_found: number;
  vulnerable_found: number;
  transport_summary?: TransportSummary | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface OriginCandidate {
  hostname: string;
  ip: string;
}

export interface TransportSummary {
  protocol?: string;
  tls_version?: string | null;
  cert_algorithm?: string | null;
  key_exchange?: string | null;
  hybrid_status?: string | null;
  pqc_active_supported?: boolean;
  pqc_active_group?: string | null;
  deployment_level?: number | null;
  deployment_level_name?: string | null;
  crypto_agility_score?: number | null;
  cdn_detected?: boolean;
  cdn_provider?: string | null;
  scan_target?: string; // "direct" | "edge"
  origin_assessed?: boolean;
  origin_note?: string | null;
  origin_candidates?: OriginCandidate[];
  // ssh
  reachable?: boolean;
  host_key?: string | null;
  pqc_kex_supported?: boolean;
}

// ── CBOM ─────────────────────────────────────────────────────────────────────
export interface Component {
  id: string;
  org_id: string;
  scan_id: string;
  asset_id?: string | null;
  location_type: string;
  location_detail: string;
  algorithm: string;
  algorithm_family: string;
  key_size?: number | null;
  quantum_status: string;
  pqc_migration_priority?: number | null;
  estimated_hndl_exposure?: string | null;
  deployment_level?: number | null;
  crypto_agility_score?: number | null;
  threat_timeline?: string | null;
  confidence?: string | null;
  cert_expiry_date?: string | null;
  cert_issuer?: string | null;
  migration_status: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface CBOMResponse {
  total: number;
  page: number;
  page_size: number;
  items: Component[];
}

export interface CBOMParams {
  quantum_status?: string;
  threat_timeline?: string;
  algorithm_family?: string;
  migration_status?: string;
  page?: string;
  page_size?: string;
}

export interface CBOMSummary {
  total_components: number;
  vulnerable: number;
  safe: number;
  hybrid: number;
  hndl_high: number;
  by_algorithm_family: Record<string, number>;
  by_threat_timeline: Record<string, number>;
  by_deployment_level: Record<string, number>;
  avg_crypto_agility_score: number;
}

// ── Risk ─────────────────────────────────────────────────────────────────────
export interface RiskScore {
  score: number;
  label: string;
  total_components: number;
  vulnerable_count: number;
  hndl_high_count: number;
  computed_at: string;
}

export interface ComplianceEntry {
  status: "PASS" | "FAIL" | "MONITOR" | "PARTIAL" | "PLANNED";
  message: string;
  checked_at: string;
}

export type ComplianceMap = Record<string, ComplianceEntry>;

export interface RoadmapBucket {
  label: string;
  count: number;
  components: {
    id: string;
    location: string;
    algorithm: string;
    action: string;
    effort_hours: string;
  }[];
}

export type Roadmap = Record<string, RoadmapBucket>;

// ── Reports ──────────────────────────────────────────────────────────────────
export interface Report {
  id: string;
  org_id: string;
  type: string;
  status: string;
  storage_path: string | null;
  component_count: number | null;
  vulnerable_count: number | null;
  risk_score_at_generation: number | null;
  error_message: string | null;
  generated_at: string | null;
  created_at: string | null;
}

// ── API Keys ─────────────────────────────────────────────────────────────────
export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  expires_at: string | null;
  created_at: string;
}

export interface ApiKeyCreated extends ApiKey {
  key: string;
}
