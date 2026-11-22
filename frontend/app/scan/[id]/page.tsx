"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  Download,
  FileJson,
  FileText,
  Radar,
} from "lucide-react";
import { api, downloadReport } from "@/lib/api";
import type { Finding, Scan, ScannersStatus, Stats, Subdomain } from "@/lib/types";
import { useLiveLogs } from "@/lib/use-live-logs";
import { cn, formatDate } from "@/lib/utils";
import { Terminal } from "@/components/terminal";
import { RiskGauge } from "@/components/risk-gauge";
import { SubdomainTree } from "@/components/subdomain-tree";
import { FindingsTable } from "@/components/findings-table";
import { FindingDrawer } from "@/components/finding-drawer";
import { ActiveChecks } from "@/components/active-checks";
import { ProgressBar, Spinner, StatusBadge } from "@/components/ui";

const STAGE_LABEL: Record<string, string> = {
  queued: "Kuyrukta",
  recon: "Subdomain Keşfi",
  httpx: "Canlı Kontrol + Tech",
  crawl: "Endpoint/Crawler",
  nuclei: "Zafiyet Taraması",
  secrets: "Secret Scan",
  "ai-triage": "AI Triage",
  reporting: "Rapor Hazırlanıyor",
  completed: "Tamamlandı",
};

export default function ScanPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;

  const [scan, setScan] = useState<Scan | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [subdomains, setSubdomains] = useState<Subdomain[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [downloading, setDownloading] = useState<"pdf" | "json" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanners, setScanners] = useState<ScannersStatus | null>(null);
  const [liveActive, setLiveActive] = useState(true);

  useEffect(() => {
    api.getScannersStatus().then(setScanners).catch(() => {});
  }, []);

  const polling = useRef(true);

  const loadAll = useCallback(async () => {
    try {
      const [data, stat] = await Promise.all([api.getScan(id), api.getStats(id)]);
      setScan(data);
      setStats(stat);
      setFindings(data.findings);
      setSubdomains(data.subdomains);
      if (data.status === "completed" || data.status === "failed") {
        polling.current = false;
        setLiveActive(false);
      }
    } catch (err) {
      if (err && typeof err === "object" && (err as { status?: number }).status === 404) {
        setNotFound(true);
        polling.current = false;
      } else {
        setError("Sunucuya bağlanılamadı");
      }
    }
  }, [id]);

  const { logs, transport } = useLiveLogs(id, liveActive);

  useEffect(() => {
    loadAll();
    const timer = setInterval(() => {
      if (!polling.current) return;
      loadAll();
    }, 2000);
    return () => clearInterval(timer);
  }, [loadAll]);

  const handleDownload = async (format: "pdf" | "json") => {
    setDownloading(format);
    try {
      await downloadReport(id, format);
    } catch (err) {
      setError(err instanceof Error ? err.message : "İndirme başarısız");
    } finally {
      setDownloading(null);
    }
  };

  if (notFound) {
    return (
      <div className="panel mx-auto mt-16 max-w-md p-8 text-center">
        <p className="mb-2 text-lg font-semibold text-zinc-200">Tarama bulunamadı</p>
        <p className="mb-4 text-sm text-muted">Bu kayıt silinmiş veya hiç var olmamış olabilir.</p>
        <Link href="/" className="btn-neon">Ana sayfaya dön</Link>
      </div>
    );
  }

  const scanning = scan?.status === "scanning" || scan?.status === "queued";
  const severityCounts = stats?.severity_counts ?? {};
  const totalFindings =
    Object.values(severityCounts).reduce((a, b) => a + b, 0) || findings.length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="panel flex flex-wrap items-center gap-4 p-4">
        <Link href="/" className="btn-ghost px-2.5 py-1.5">
          <ArrowLeft className="h-4 w-4" />
        </Link>
        <div className="min-w-0">
          <div className="flex items-center gap-3">
            <Radar className={cn("h-5 w-5 text-neon", scanning && "animate-pulse-neon")} />
            <h1 className="truncate font-mono text-xl font-bold text-zinc-100">
              {scan?.target_domain ?? "…"}
            </h1>
            <StatusBadge status={scan?.status ?? "queued"} />
          </div>
          <p className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
            <span>#{id}</span>·
            <span>{scan?.scan_type === "deep" ? "Derin" : "Hızlı"}</span>·
            <span>{formatDate(scan?.created_at)}</span>
            {scan?.meta?.ai && (
              <span className="rounded border border-neon-dark bg-black/50 px-1.5 py-0.5 font-mono text-[10px] text-neon-dim">
                AI: {scan.meta.ai.provider}
                {scan.meta.ai.model ? ` · ${scan.meta.ai.model}` : ""}
              </span>
            )}
          </p>
        </div>

        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => handleDownload("pdf")}
            disabled={downloading !== null || !scan || scanning}
            className="btn-neon px-3 py-2 text-xs"
          >
            {downloading === "pdf" ? <Spinner /> : <FileText className="h-4 w-4" />}
            PDF İndir
          </button>
          <button
            onClick={() => handleDownload("json")}
            disabled={downloading !== null || !scan || scanning}
            className="btn-ghost px-3 py-2 text-xs"
          >
            {downloading === "json" ? <Spinner /> : <FileJson className="h-4 w-4" />}
            JSON
          </button>
        </div>
      </div>

      {scanners && (scanners.demo_mode || scanners.items.some((i) => !i.found)) && (
        <div
          className={cn(
            "rounded-lg border px-3 py-2 text-xs",
            scanners.demo_mode
              ? "border-neon-dark bg-neon-dark/15 text-neon"
              : "border-yellow-900 bg-yellow-950/30 text-yellow-300"
          )}
        >
          {scanners.demo_mode
            ? "DEMO modu aktif — bu tarama sentetik hedef/bulgu üretir. Gerçek tarama için DEMO_MODE=false yapın."
            : `Tarayıcı binary'leri eksik: ${scanners.items.filter((i) => !i.found).map((i) => i.name).join(", ")}. Yerleşik fallback motoru kullanılır; en iyi sonuç için Docker imajını kullanın (bkz. README Bölüm 2/5).`}
        </div>
      )}

      {error && (
        <p className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-400">
          {error}
        </p>
      )}

      {/* Progress + risk */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="panel p-4 lg:col-span-2">
          <div className="mb-2 flex items-center justify-between text-xs">
            <span className="label-neon">
              {STAGE_LABEL[scan?.current_stage ?? "queued"] ?? scan?.current_stage}
            </span>
            <span className="font-mono text-neon">%{scan?.progress ?? 0}</span>
          </div>
          <ProgressBar value={scan?.progress ?? 0} />
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "Kritik", value: severityCounts.critical ?? 0, color: "text-red-400" },
              { label: "Yüksek", value: severityCounts.high ?? 0, color: "text-orange-400" },
              { label: "Orta", value: severityCounts.medium ?? 0, color: "text-yellow-400" },
              { label: "Düşük", value: severityCounts.low ?? 0, color: "text-green-400" },
            ].map((s) => (
              <div key={s.label} className="rounded-lg border border-line bg-black/40 p-3 text-center">
                <p className={cn("font-mono text-2xl font-bold", s.color)}>{s.value}</p>
                <p className="text-[10px] uppercase tracking-widest text-muted">{s.label}</p>
              </div>
            ))}
          </div>
          {stats && (
            <p className="mt-3 text-[11px] text-muted">
              {stats.subdomains_alive}/{stats.subdomains_total} alt alan canlı ·{" "}
              {stats.false_positives} false positive · toplam {totalFindings} bulgu
            </p>
          )}
          {scan?.meta?.warning === "no_findings" && (
            <p className="mt-2 rounded border border-yellow-900 bg-yellow-950/30 px-2 py-1.5 text-[11px] text-yellow-300">
              Bu tarama 0 bulgu üretti. Hedef erişilebilir mi? Tarayıcı binary&#39;leri
              kurulu mu (bakınız: Tarayıcılar satırı / /api/scanners/status)?
            </p>
          )}
          {stats?.engines && Object.keys(stats.engines).length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {Object.entries(stats.engines).map(([stage, engine]) => (
                <span
                  key={stage}
                  className="rounded border border-line bg-black/50 px-1.5 py-0.5 text-[10px] text-muted"
                >
                  {stage}: <span className="text-neon-dim">{engine}</span>
                </span>
              ))}
            </div>
          )}
        </div>
        <div className="panel flex items-center justify-center p-4">
          <RiskGauge score={scan?.risk_score ?? 0} />
        </div>
      </div>

      {/* Main grid */}
      <div className="grid gap-4 lg:grid-cols-12">
        <div className="lg:col-span-4">
          <Terminal logs={logs} scanning={scanning} transport={transport} />
        </div>
        <div className="lg:col-span-5">
          <FindingsTable findings={findings} onSelect={setSelected} />
        </div>
        <div className="lg:col-span-3">
          <SubdomainTree subdomains={subdomains} />
        </div>
      </div>

      {scan?.meta?.client_inventory && (
        <section className="panel space-y-3 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="label-neon">İstemci kaynak envanteri · {scan.meta.client_inventory.status}</h2>
            {scan.meta.client_inventory.archive_available && (
              <div className="flex gap-2">
                <a className="btn-ghost text-xs" href={`/api/scans/${id}/client-inventory/archive`} download>
                  <Download className="h-4 w-4" /> Kaynak arşivi
                </a>
                <a className="btn-ghost text-xs" href={`/api/scans/${id}/client-inventory/reconstruction`} download>
                  <Download className="h-4 w-4" /> Görsel kopya + JS
                </a>
              </div>
            )}
          </div>
          <p className="text-xs text-yellow-300">Bu arşiv güvenilmeyen, hassas veri içerebilen ham istemci dosyalarıdır. Çalıştırmayın veya güvenilir bir sunucuda yayınlamayın. Sunucu kodu ve veritabanı içermez; çalışan bir site kopyası değildir.</p>
          <p className="text-xs text-muted">Görsel kopya etkileşimli uygulama değildir: scriptler ve formlar devre dışıdır; indirme ayrıca güzelleştirilmiş JS içerir.</p>
          <p className="text-xs text-muted">{scan.meta.client_inventory.files.length} dosya · {scan.meta.client_inventory.forms.length} form · {scan.meta.client_inventory.api_paths.length} API yolu adayı · {scan.meta.client_inventory.source_maps.length} source map. Adaylar doğrulanmış güvenlik açığı değildir.</p>
          <details className="text-xs text-zinc-300"><summary className="cursor-pointer text-neon-dim">Dosyalar ve source map’ler</summary><ul className="mt-2 space-y-1 break-all">{scan.meta.client_inventory.files.map((file) => <li key={file.file}>{file.url} — {file.bytes} bayt</li>)}{scan.meta.client_inventory.source_maps.map((map) => <li key={map.url}>Source map: {map.sources.length} kaynak, {map.embedded_sources} gömülü içerik — {map.url}<ul className="ml-4 text-muted">{map.sources.map((source, i) => <li key={i}>{source}</li>)}</ul></li>)}</ul></details>
          <details className="text-xs text-zinc-300"><summary className="cursor-pointer text-neon-dim">Formlar ve parametreler</summary><ul className="mt-2 space-y-1 break-all">{scan.meta.client_inventory.forms.map((form, i) => <li key={i}>{form.method} {form.action} · {form.fields.join(", ")}</li>)}<li>URL parametreleri: {scan.meta.client_inventory.parameters.join(", ") || "yok"}</li></ul></details>
          {(scan.meta.client_inventory.manual_review?.length ?? 0) > 0 && <details className="text-xs text-zinc-300"><summary className="cursor-pointer text-yellow-300">Manuel inceleme adayları ({scan.meta.client_inventory.manual_review?.length}) — test edilmedi</summary><ul className="mt-2 space-y-2 break-all">{scan.meta.client_inventory.manual_review?.map((item, i) => <li key={i}><span className="font-semibold">{item.category}</span> · {item.url}<br />{item.reason}</li>)}</ul></details>}
          <details className="text-xs text-zinc-300"><summary className="cursor-pointer text-neon-dim">JavaScript / OpenAPI yol adayları</summary><ul className="mt-2 space-y-1 break-all">{scan.meta.client_inventory.api_paths.map((path) => <li key={path}>{path}</li>)}</ul></details>
        </section>
      )}
      {scan?.status === "completed" && <ActiveChecks id={id} results={scan.meta?.active_checks} onCompleted={() => { void loadAll(); }} />}
      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
