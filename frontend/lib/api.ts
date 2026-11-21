import type {
  Finding,
  ProviderInfo,
  Scan,
  ScanDiff,
  ScanListResponse,
  ScanLog,
  ScannersStatus,
  SettingsState,
  Stats,
  Subdomain,
} from "./types";

const BASE = "/api";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    });
  } catch {
    throw new ApiError(0, "Ag baglantisi kurulamadi");
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export interface CreateScanInput {
  domain: string;
  scan_type: "fast" | "deep";
  authorized: boolean;
  ai_provider?: string;
}

export const api = {
  createScan: (input: CreateScanInput) =>
    request<Scan>("/scans", { method: "POST", body: JSON.stringify(input) }),

  listScans: (limit = 50, offset = 0) =>
    request<ScanListResponse>(`/scans?limit=${limit}&offset=${offset}`),

  getScan: (id: number | string) => request<Scan & {
    findings: Finding[];
    subdomains: Subdomain[];
  }>(`/scans/${id}`),

  getLogs: (id: number | string, afterId = 0, limit = 500) =>
    request<{ items: ScanLog[]; last_id: number }>(
      `/scans/${id}/logs?after_id=${afterId}&limit=${limit}`
    ),

  getFindings: (
    id: number | string,
    params: { severity?: string; q?: string; include_fp?: boolean; type?: string } = {}
  ) => {
    const qs = new URLSearchParams();
    if (params.severity) qs.set("severity", params.severity);
    if (params.q) qs.set("q", params.q);
    if (params.include_fp) qs.set("include_fp", "true");
    if (params.type) qs.set("type", params.type);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request<{ items: Finding[]; total: number }>(`/scans/${id}/findings${suffix}`);
  },

  getSubdomains: (id: number | string, alive?: boolean) =>
    request<{ items: Subdomain[]; total: number }>(
      `/scans/${id}/subdomains${alive === undefined ? "" : `?alive=${alive}`}`
    ),

  getStats: (id: number | string) => request<Stats>(`/scans/${id}/stats`),

  getProviders: () =>
    request<{ items: ProviderInfo[]; auto_priority: string[] }>("/providers"),

  getScannersStatus: () => request<ScannersStatus>("/scanners/status"),

  getSettings: () => request<SettingsState>("/settings"),

  updateSettings: (input: {
    provider?: string;
    model?: string;
    base_url?: string;
    api_key?: string;
  }) =>
    request<SettingsState>("/settings", {
      method: "PUT",
      body: JSON.stringify(input),
    }),

  diffScans: (fromId: number | string, toId: number | string) =>
    request<ScanDiff>(`/scans/diff?from=${fromId}&to=${toId}`),

  reportUrl: (id: number | string, format: "pdf" | "json") =>
    `${BASE}/scans/${id}/report?format=${format}`,
};

/** POST the report endpoint and trigger a browser download. */
export async function downloadReport(id: number | string, format: "pdf" | "json") {
  const res = await fetch(`${BASE}/scans/${id}/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ format }),
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = String(body.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `raven-report-${id}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
