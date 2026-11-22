"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Cpu, PlugZap, Settings2, Wrench } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { ProviderInfo, Scan, ScannersStatus, SettingsState } from "@/lib/types";
import { formatDate } from "@/lib/utils";
import { ProviderSettingsForm } from "./provider-settings-form";
import { Spinner } from "./ui";

export function SettingsClient() {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [scanners, setScanners] = useState<ScannersStatus | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [prov, st, sc, recent] = await Promise.all([
        api.getProviders(),
        api.getSettings(),
        api.getScannersStatus(),
        api.listScans(5, 0),
      ]);
      setProviders(prov.items);
      setSettings(st);
      setScanners(sc);
      setScans(recent.items);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Ayarlar yüklenemedi");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const lastAi = scans.find((s) => s.meta?.ai?.provider);

  const handleLoaded = useCallback((st: SettingsState, prov: ProviderInfo[]) => {
    setSettings(st);
    setProviders(prov);
  }, []);

  const handleSaved = useCallback(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-neon-dim">
        <Spinner className="mr-2 h-5 w-5" /> Ayarlar yükleniyor…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-zinc-100">
          <Settings2 className="h-6 w-6 text-neon" /> Ayarlar
        </h1>
        <p className="mt-1 text-sm text-muted">
          AI sağlayıcılarını yapılandır, API anahtarlarını kaydet ve bağlantıyı
          doğrula. Tarayıcı binary&apos;lerinin durumunu gör.
        </p>
      </div>

      {error && (
        <p className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-400">
          {error}
        </p>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="panel p-5">
          <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-zinc-100">
            <PlugZap className="h-5 w-5 text-neon" /> AI Sağlayıcı
          </h2>
          <ProviderSettingsForm onSaved={handleSaved} onLoaded={handleLoaded} />
        </section>

        <div className="space-y-6">
          <section className="panel p-5">
            <h2 className="mb-3 flex items-center gap-2 text-lg font-semibold text-zinc-100">
              <Cpu className="h-5 w-5 text-neon" /> AI Çalışıyor mu?
            </h2>
            {lastAi?.meta?.ai ? (
              <div className="space-y-2 text-sm">
                <p className="text-zinc-300">
                  Son taramada kullanılan motor:{" "}
                  <span className="font-mono text-neon">
                    {lastAi.meta.ai.provider} · {lastAi.meta.ai.model}
                  </span>
                </p>
                <p className="text-[11px] text-muted">
                  Tarama #{lastAi.id} · {lastAi.target_domain} ·{" "}
                  {formatDate(lastAi.created_at)}
                </p>
                <Link
                  href={`/scan/${lastAi.id}`}
                  className="inline-block text-xs text-neon-dim underline-offset-2 hover:underline"
                >
                  Tarama raporunu aç →
                </Link>
              </div>
            ) : (
              <p className="text-sm text-muted">
                Henüz AI&apos;lı tamamlanmış bir tarama yok. Bir sağlayıcı
                kaydedip <span className="text-neon-dim">Test Et</span> ile
                doğruladıktan sonra tarama başlatın; burada göreceksiniz.
              </p>
            )}
          </section>

          <section className="panel p-5">
            <h2 className="mb-3 flex items-center gap-2 text-lg font-semibold text-zinc-100">
              <Wrench className="h-5 w-5 text-neon" /> Tarayıcılar
            </h2>
            <ul className="space-y-2 text-sm">
              {(scanners?.items ?? []).map((item) => (
                <li key={item.name} className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-zinc-300">{item.name}</span>
                  <span
                    className={
                      item.found
                        ? "text-xs text-neon"
                        : "rounded border border-line px-1.5 py-0.5 text-[10px] text-muted"
                    }
                  >
                    {item.found ? item.version || "kurulu" : "yok (yerlesik motor)"}
                  </span>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-[11px] text-muted">
              Binary yoksa RAVEN aynı işi yapan yerleşik Python motorlarını
              kullanır; rapora etkilenen her bulgu motor sütununda görünür.
            </p>
          </section>
        </div>
      </div>

      <section className="panel overflow-hidden">
        <h2 className="border-b border-line px-5 py-3 text-lg font-semibold text-zinc-100">
          Sağlayıcılar
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-[11px] uppercase tracking-wider text-muted">
              <tr>
                <th className="px-5 py-2.5">Sağlayıcı</th>
                <th className="px-5 py-2.5">Model</th>
                <th className="px-5 py-2.5">Uç nokta</th>
                <th className="px-5 py-2.5">Anahtar</th>
                <th className="px-5 py-2.5">Durum</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((p) => {
                const cfg = settings?.providers?.[p.id];
                return (
                  <tr key={p.id} className="border-b border-line/60 last:border-0">
                    <td className="px-5 py-2.5">
                      <div className="text-zinc-200">{p.label}</div>
                      <div className="text-[11px] text-muted">
                        {p.openai_compatible ? "OpenAI uyumlu" : "native API"}
                        {p.requires_key ? " · anahtar gerekli" : " · anahtarsız"}
                      </div>
                    </td>
                    <td className="px-5 py-2.5 font-mono text-xs text-zinc-300">
                      {cfg?.model || p.default_model}
                    </td>
                    <td className="max-w-[220px] truncate px-5 py-2.5 font-mono text-[11px] text-muted">
                      {cfg?.base_url || p.base_url || "—"}
                    </td>
                    <td className="px-5 py-2.5 font-mono text-xs text-zinc-300">
                      {cfg?.api_key_set ? cfg.api_key : "—"}
                    </td>
                    <td className="px-5 py-2.5">
                      <span
                        className={
                          p.configured
                            ? "rounded border border-neon-dim/50 bg-neon/10 px-2 py-0.5 text-[11px] text-neon"
                            : "rounded border border-line px-2 py-0.5 text-[11px] text-muted"
                        }
                      >
                        {p.configured ? "yapılandırıldı" : "bekliyor"}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
