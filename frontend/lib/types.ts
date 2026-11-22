export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "queued" | "scanning" | "completed" | "failed";

export interface Scan {
  id: number;
  target_domain: string;
  scan_type: "fast" | "deep";
  status: ScanStatus;
  progress: number;
  current_stage: string;
  risk_score: number;
  authorized: boolean;
  error: string | null;
  meta: {
    executive_summary?: string;
    engines?: Record<string, string>;
    counts?: Record<string, number>;
    ai?: { provider: string; model: string };
    ai_provider?: string;
    warning?: string;
    client_inventory?: ClientInventory;
  };
  created_at: string | null;
  completed_at: string | null;
  finding_count?: number;
}

export interface ClientInventory {
  status: string;
  archive_available: boolean;
  files: { url: string; file: string; content_type: string; bytes: number }[];
  forms: { page: string; action: string; method: string; fields: string[] }[];
  api_paths: string[];
  parameters: string[];
  source_maps: { url: string; sources: string[]; embedded_sources: number }[];
}

export interface Finding {
  id: number;
  scan_id: number;
  type: string;
  title: string;
  severity: Severity;
  cvss: number | null;
  url: string | null;
  evidence: string | null;
  ai_analysis: string | null;
  exploit_scenario: string | null;
  fix_code: string | null;
  is_false_positive: boolean;
  owasp_category: string | null;
  source: string;
  ai_provider?: string | null;
  ai_confidence?: number | null;
}

export interface Subdomain {
  id: number;
  subdomain: string;
  ip: string | null;
  is_alive: boolean;
  technologies: string[];
  ports: number[];
  status_code: number | null;
  title: string | null;
}

export interface ScanLog {
  id: number;
  scan_id: number;
  level: string;
  message: string;
  ts: string | null;
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  limit: number;
  offset: number;
}

export interface DiffFinding {
  title: string;
  url: string;
  severity: string;
}

export interface ScanDiff {
  from: { id: number; domain: string; risk_score: number; created_at: string };
  to: { id: number; domain: string; risk_score: number; created_at: string };
  added: DiffFinding[];
  removed: DiffFinding[];
  risk_delta: number;
}

export interface ScannerStatusItem {
  name: string;
  path: string | null;
  found: boolean;
  version: string | null;
}

export interface ScannersStatus {
  items: ScannerStatusItem[];
  demo_mode: boolean;
}

export interface ProviderInfo {
  id: string;
  label: string;
  description: string;
  base_url: string | null;
  default_model: string;
  key_env: string | null;
  requires_key: boolean;
  openai_compatible: boolean;
  docs: string;
  configured: boolean;
}

export interface ProviderSettings {
  model: string | null;
  base_url: string | null;
  api_key: string | null;
  api_key_set: boolean;
  configured: boolean;
}

export interface SettingsState {
  provider: string;
  providers: Record<string, ProviderSettings>;
  auto_priority: string[];
}

export interface Stats {
  scan_id: number;
  status: ScanStatus;
  progress: number;
  risk_score: number;
  severity_counts: Record<string, number>;
  false_positives: number;
  subdomains_total: number;
  subdomains_alive: number;
  findings_total: number;
  engines: Record<string, string>;
}
