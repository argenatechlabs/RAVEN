"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { GitCompare, History, RefreshCw, Search } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { Scan, ScanDiff } from "@/lib/types";
import { cn, formatDate } from "@/lib/utils";
import { EmptyState, Spinner, StatusBadge } from "@/components/ui";

export default function HistoryPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<string>("all");
  const [rescanning, setRescanning] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [diffFrom, setDiffFrom] = useState("");
  const [diffTo, setDiffTo] = useState("");
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);

  const compare = async () => {
    if (!diffFrom || !diffTo || diffFrom === diffTo) {
      setError("Karşılaştırmak için iki farklı tarama seçin");
      return;
    }
    setDiffLoading(true);
    try {
      setDiff(await api.diffScans(diffFrom, diffTo));
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Karşılaştırma başarısız");
    } finally {
      setDiffLoading(false);
    }
  };

  const load = useCallback(async () => {
    try {
      const res = await api.listScans(100, 0);
      setScans(res.items);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Geçmiş yüklenemedi");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 8000);
    return () => clearInterval(timer);
  }, [load]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return scans.filter((s) => {
      if (status !== "all" && s.status !== status) return false;
      if (q && !s.target_domain.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [scans, query, status]);

  const rescan = async (scan: Scan) => {
    setRescanning(scan.id);
    setError(null);
    try {
      const created = await api.createScan({
        domain: scan.target_domain,
        scan_type: scan.scan_type,
        authorized: true,
      });
      router.push(`/scan/${created.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Tarama başlatılamadı");
      setRescanning(null);
    }
  };

  const completed = scans.filter((s) => s.status === "completed").length;
  const avgRisk = completed
    ? Math.round(
        scans.filter((s) => s.status === "completed")
          .reduce((a, s) => a + s.risk_score, 0) / completed
      )
    : 0;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-zinc-100">
            <History className="h-6 w-6 text-neon" /> Tarama Geçmişi
          </h1>
          <p className="mt-1 text-xs text-muted">
            {scans.length} tarama · {completed} tamamlandı · ortalama risk {avgRisk}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Domain ara…"
              className="input-neon w-56 py-2 pl-9 text-sm"
            />
          </div>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="input-neon w-36 py-2 text-sm"
          >
            <option value="all">Tüm durumlar</option>
            <option value="completed">Tamamlandı</option>
            <option value="scanning">Sürüyor</option>
            <option value="queued">Kuyrukta</option>
            <option value="failed">Başarısız</option>
          </select>
        </div>
      </div>

      {error && (
        <p className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-400">
          {error}
        </p>
      )}

      {/* Diff */}
      <div className="panel p-4">
        <h2 className="label-neon mb-3 flex items-center gap-2">
          <GitCompare className="h-4 w-4 text-neon" /> Tarama Karşılaştırma (diff)
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={diffFrom}
            onChange={(e) => setDiffFrom(e.target.value)}
            className="input-neon w-52 py-2 text-xs"
          >
            <option value="">Eski tarama…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                #{s.id} {s.target_domain}
              </option>
            ))}
          </select>
          <span className="text-neon-dim">→</span>
          <select
            value={diffTo}
            onChange={(e) => setDiffTo(e.target.value)}
            className="input-neon w-52 py-2 text-xs"
          >
            <option value="">Yeni tarama…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                #{s.id} {s.target_domain}
              </option>
            ))}
          </select>
          <button
            onClick={compare}
            disabled={diffLoading}
            className="btn-neon px-4 py-2 text-xs"
          >
            {diffLoading ? <Spinner /> : <GitCompare className="h-3.5 w-3.5" />}
            Karşılaştır
          </button>
        </div>

        {diff && (
          <div className="mt-4 space-y-3">
            <p className="text-xs text-muted">
              Risk değişimi:{" "}
              <span
                className={cn(
                  "font-mono",
                  diff.risk_delta > 0 ? "text-red-400" : diff.risk_delta < 0 ? "text-green-400" : "text-zinc-400"
                )}
              >
                {diff.risk_delta > 0 ? "+" : ""}
                {diff.risk_delta}
              </span>{" "}
              ({diff.from.risk_score} → {diff.to.risk_score})
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-red-900/60 bg-red-950/20 p-3">
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-red-400">
                  Yeni bulgular ({diff.added.length})
                </p>
                {diff.added.length === 0 ? (
                  <p className="text-xs text-muted">Yeni bulgu yok.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {diff.added.map((f, i) => (
                      <li key={i} className="text-xs text-zinc-300">
                        <span className="font-mono text-red-400">[{f.severity}]</span> {f.title}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="rounded-lg border border-green-900/60 bg-green-950/20 p-3">
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-green-400">
                  Giderilen bulgular ({diff.removed.length})
                </p>
                {diff.removed.length === 0 ? (
                  <p className="text-xs text-muted">Giderilen bulgu yok.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {diff.removed.map((f, i) => (
                      <li key={i} className="text-xs text-zinc-300">
                        <span className="font-mono text-green-400">[{f.severity}]</span> {f.title}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="panel overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-12 text-muted">
            <Spinner /> Yükleniyor…
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<History className="h-8 w-8" />}
            title="Tarama bulunamadı"
            hint="Filtreyi temizleyin veya yeni bir tarama başlatın"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-line text-[11px] uppercase tracking-wider text-muted">
                  <th className="px-4 py-3">Domain</th>
                  <th className="px-4 py-3">Tip</th>
                  <th className="px-4 py-3">Durum</th>
                  <th className="px-4 py-3 text-right">Risk</th>
                  <th className="px-4 py-3 text-right">Bulgu</th>
                  <th className="px-4 py-3">Tarih</th>
                  <th className="px-4 py-3 text-right">İşlem</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => (
                  <tr
                    key={s.id}
                    className="border-b border-line/60 transition hover:bg-neon-dark/15"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/scan/${s.id}`}
                        className="font-mono text-zinc-200 hover:text-neon"
                      >
                        {s.target_domain}
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">
                      {s.scan_type === "deep" ? "Derin" : "Hızlı"}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={s.status} />
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-neon">
                      {s.risk_score}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-zinc-300">
                      {s.finding_count ?? 0}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">{formatDate(s.created_at)}</td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Link href={`/scan/${s.id}`} className="btn-ghost px-2.5 py-1 text-xs">
                          Aç
                        </Link>
                        <button
                          onClick={() => rescan(s)}
                          disabled={rescanning === s.id}
                          className="btn-ghost px-2.5 py-1 text-xs"
                          title="Tekrar tara"
                        >
                          {rescanning === s.id ? (
                            <Spinner className="h-3.5 w-3.5" />
                          ) : (
                            <RefreshCw className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
