"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Activity,
  Bug,
  Crosshair,
  Globe,
  History,
  Radar,
  Search,
  Settings2,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { ProviderInfo, Scan } from "@/lib/types";
import { cn, formatDate } from "@/lib/utils";
import { Spinner, StatusBadge } from "@/components/ui";
import { AiProviderSelect, AiSettingsModal } from "@/components/ai-settings";

export default function HomePage() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [scanType, setScanType] = useState<"fast" | "deep">("fast");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<Scan[]>([]);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [providerId, setProviderId] = useState("auto");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [providerError, setProviderError] = useState<string | null>(null);

  const loadAi = useCallback(async () => {
    try {
      const [prov, st] = await Promise.all([api.getProviders(), api.getSettings()]);
      setProviders(prov.items);
      setProviderId(st.provider || "auto");
      setProviderError(null);
    } catch (err) {
      setProviderError(err instanceof ApiError ? err.message : "AI ayarlari yuklenemedi");
    }
  }, []);

  useEffect(() => {
    loadAi();
  }, [loadAi]);

  const changeProvider = useCallback(async (id: string) => {
    setProviderId(id);
    try {
      await api.updateSettings({ provider: id });
    } catch {
      /* seçim arayüzde yansıtılsın; hata modalda gösterilir */
    }
  }, []);

  const loadRecent = useCallback(async () => {
    try {
      const res = await api.listScans(3, 0);
      setRecent(res.items);
    } catch {
      /* backend henüz hazır değil */
    }
  }, []);

  useEffect(() => {
    loadRecent();
    const timer = setInterval(loadRecent, 8000);
    return () => clearInterval(timer);
  }, [loadRecent]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!domain.trim()) {
      setError("Lütfen bir domain girin");
      return;
    }
    if (!authorized) {
      setError("Devam etmek için yasal onay kutusunu işaretleyin");
      return;
    }
    setLoading(true);
    try {
      const scan = await api.createScan({
        domain: domain.trim(),
        scan_type: scanType,
        authorized: true,
        ai_provider: providerId,
      });
      router.push(`/scan/${scan.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Tarama başlatılamadı");
      setLoading(false);
    }
  };

  return (
    <div className="space-y-10">
      {/* Hero */}
      <section className="mx-auto max-w-3xl pt-8 text-center">
        <div className="mb-4 flex justify-center">
          <span className="flex h-16 w-16 items-center justify-center rounded-2xl border border-neon-dim bg-neon-dark/30 shadow-glow">
            <Radar className="h-9 w-9 animate-pulse-neon text-neon" />
          </span>
        </div>
        <h1 className="text-4xl font-bold tracking-tight text-zinc-100 sm:text-5xl">
          Otonom <span className="neon-text">AI</span> Sızma Testi
        </h1>
        <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-muted">
          Domain girin; RAVEN subdomain keşfi, canlı tarama, 9.000+ imza ile
          güvenlik taraması, secret scan ve AI triage&apos;yi otomatik çalıştırır,
          ardından profesyonel PDF raporu hazırlar.
        </p>

        <form onSubmit={submit} className="mt-8 space-y-4 text-left">
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="relative flex-1">
              <Globe className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-neon-dim" />
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="testphp.vulnweb.com"
                className="input-neon pl-10"
                autoFocus
              />
            </div>
            <button type="submit" disabled={loading} className="btn-neon sm:w-40">
              {loading ? <Spinner /> : <Search className="h-4 w-4" />}
              {loading ? "Başlatılıyor" : "Tara"}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <div className="flex overflow-hidden rounded-lg border border-line">
              {(["fast", "deep"] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setScanType(t)}
                  className={cn(
                    "flex items-center gap-1.5 px-4 py-2 text-xs font-semibold transition",
                    scanType === t
                      ? "bg-neon-dark/40 text-neon"
                      : "bg-black/40 text-zinc-400 hover:text-zinc-200"
                  )}
                >
                  <Zap className="h-3.5 w-3.5" />
                  {t === "fast" ? "Hızlı" : "Derin"}
                </button>
              ))}
            </div>
            <label className="flex cursor-pointer items-start gap-2 text-xs text-zinc-400">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[#00ff41]"
              />
              <span className="leading-5">
                <ShieldCheck className="mr-1 inline h-3.5 w-3.5 text-neon-dim" />
                Sadece izinli hedeflerde tarama yapacağımı onaylıyorum.
              </span>
            </label>
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <div className="w-64">
              <label className="label-neon mb-1 block">AI Sağlayıcı</label>
              <AiProviderSelect
                providers={providers}
                value={providerId}
                onChange={changeProvider}
              />
            </div>
            <button
              type="button"
              onClick={() => setSettingsOpen(true)}
              className="btn-ghost px-3 py-2 text-xs"
            >
              <Settings2 className="h-4 w-4" /> API Anahtarı / Model
            </button>
          </div>

          {(error || providerError) && (
            <p className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-400">
              {error || providerError}
            </p>
          )}
        </form>
      </section>

      {/* Pipeline */}
      <section className="grid gap-3 sm:grid-cols-3">
        {[
          { icon: <Activity className="h-5 w-5" />, title: "Recon + Crawl",
            desc: "subfinder, httpx ve katana ile alt alan, canlı host, endpoint ve JS keşfi." },
          { icon: <Bug className="h-5 w-5" />, title: "9.000+ İmza",
            desc: "nuclei ile critical/high/medium zafiyet taraması + JS secret scan." },
          { icon: <Crosshair className="h-5 w-5" />, title: "AI Triage + PDF",
            desc: "OpenAI/Ollama ile false positive eleme, sömürü senaryosu ve fix kodu." },
        ].map((c) => (
          <div key={c.title} className="panel p-4">
            <div className="mb-2 flex items-center gap-2 text-neon">
              {c.icon}
              <h3 className="text-sm font-semibold text-zinc-200">{c.title}</h3>
            </div>
            <p className="text-xs leading-5 text-muted">{c.desc}</p>
          </div>
        ))}
      </section>

      {/* Recent */}
      <section>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="label-neon flex items-center gap-2">
            <History className="h-4 w-4 text-neon" /> Son Taramalar
          </h2>
          <Link href="/history" className="text-xs text-neon-dim hover:text-neon">
            Tümünü gör →
          </Link>
        </div>
        {recent.length === 0 ? (
          <div className="panel p-6 text-center text-sm text-muted">
            Henüz tarama yok — yukarıya hedef domaininizi girin.
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-3">
            {recent.map((s) => (
              <Link
                key={s.id}
                href={`/scan/${s.id}`}
                className="panel group p-4 transition hover:border-neon-dim hover:shadow-glow-sm"
              >
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-sm text-zinc-200 group-hover:text-neon">
                    {s.target_domain}
                  </span>
                  <StatusBadge status={s.status} />
                </div>
                <div className="flex items-center justify-between text-[11px] text-muted">
                  <span>{formatDate(s.created_at)}</span>
                  <span>
                    risk <span className="font-mono text-neon">{s.risk_score}</span>
                    {typeof s.finding_count === "number" && ` · ${s.finding_count} bulgu`}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>

      <AiSettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onSaved={(p) => setProviderId(p)}
      />
    </div>
  );
}
