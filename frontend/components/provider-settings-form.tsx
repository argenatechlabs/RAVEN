"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, KeyRound, Loader2, Zap } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { ProviderInfo, SettingsState } from "@/lib/types";
import { AiProviderSelect } from "./ai-settings";

type TestResult = { ok: boolean; message: string } | null;

/**
 * Full AI-provider editor: pick a provider, store its API key/model/endpoint
 * and verify the credentials with a one-line probe. Shared by the dashboard
 * modal and the dedicated /settings page.
 */
export function ProviderSettingsForm({
  onSaved,
  onLoaded,
}: {
  onSaved?: (provider: string) => void;
  onLoaded?: (settings: SettingsState, providers: ProviderInfo[]) => void;
}) {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [provider, setProvider] = useState("auto");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<TestResult>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    try {
      const [prov, st] = await Promise.all([api.getProviders(), api.getSettings()]);
      setProviders(prov.items);
      setSettings(st);
      setProvider(st.provider);
      const cfg = st.providers[st.provider];
      setModel(cfg?.model ?? "");
      setBaseUrl(cfg?.base_url ?? "");
      setApiKey("");
      setError(null);
      onLoaded?.(st, prov.items);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Ayarlar yüklenemedi");
    }
  }, [onLoaded]);

  useEffect(() => {
    load();
  }, [load]);

  const current: ProviderInfo | undefined = providers.find((p) => p.id === provider);
  const selectedCfg = settings?.providers?.[provider];

  const changeProvider = (id: string) => {
    setProvider(id);
    const cfg = settings?.providers?.[id];
    setModel(cfg?.model ?? "");
    setBaseUrl(cfg?.base_url ?? "");
    setApiKey("");
    setSaved(false);
    setTestResult(null);
  };

  /** Show the stored key placeholder when one exists, but never the key itself. */
  const keyHint = selectedCfg?.api_key_set ? selectedCfg.api_key : null;

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updateSettings({
        provider,
        model: model.trim() || undefined,
        base_url: baseUrl.trim() || undefined,
        // An empty field means "keep what is already stored" — the server
        // cannot hand the secret back, so we never send an empty key by accident.
        api_key: apiKey.trim() || undefined,
        keep_api_key: !apiKey.trim(),
      });
      setSettings(updated);
      setApiKey("");
      setSaved(true);
      onSaved?.(provider);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Kaydedilemedi");
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async () => {
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      // Persist first: the endpoint tests the *stored* configuration.
      const updated = await api.updateSettings({
        provider,
        model: model.trim() || undefined,
        base_url: baseUrl.trim() || undefined,
        api_key: apiKey.trim() || undefined,
        keep_api_key: !apiKey.trim(),
      });
      setSettings(updated);
      setApiKey("");
      const result = await api.testProvider(provider);
      setTestResult({
        ok: true,
        message: `${result.model} · ${result.latency_ms} ms · ${result.reply}`,
      });
      onSaved?.(provider);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Baglanti testi basarisiz";
      setTestResult({ ok: false, message });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="label-neon mb-1.5 block">Sağlayıcı</label>
        <AiProviderSelect
          providers={providers}
          value={provider}
          onChange={changeProvider}
        />
        {current && <p className="mt-1.5 text-[11px] text-muted">{current.description}</p>}
      </div>

      {provider !== "auto" && provider !== "local" && (
        <>
          <div>
            <label className="label-neon mb-1.5 block">Model</label>
            <input
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder={current?.default_model || "model adi"}
              className="input-neon py-2 text-sm"
            />
            <p className="mt-1 text-[11px] text-muted">
              Örn: <span className="font-mono text-neon-dim">grok-3</span>,{" "}
              <span className="font-mono text-neon-dim">gemini-2.5-flash</span>,{" "}
              <span className="font-mono text-neon-dim">claude-sonnet-4-5</span>
            </p>
          </div>

          {provider === "custom" && (
            <div>
              <label className="label-neon mb-1.5 block">Base URL (OpenAI uyumlu)</label>
              <input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://api.ornek.com/v1"
                className="input-neon py-2 text-sm"
              />
            </div>
          )}

          <div>
            <label className="label-neon mb-1.5 flex items-center gap-1.5">
              <KeyRound className="h-3.5 w-3.5" /> API Anahtarı
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={
                keyHint ? `Kayıtlı: ${keyHint} (değiştirmek için yeni girin)` : "API anahtarinizi girin"
              }
              className="input-neon py-2 text-sm"
              autoComplete="off"
            />
            <p className="mt-1 text-[11px] text-muted">
              Anahtarlar sunucuda saklanır ve API yanıtında asla döndürülmez.
            </p>
          </div>
        </>
      )}

      {provider === "auto" && settings && (
        <div>
          <label className="label-neon mb-1.5 block">Otomatik öncelik</label>
          <p className="font-mono text-xs text-neon-dim">
            {settings.auto_priority.join(" → ")}
          </p>
          <p className="mt-1 text-[11px] text-muted">
            AI_PROVIDER=auto olduğunda RAVEN bu sırayla ilk kullanılabilir
            sağlayıcıyı seçer; hiçbiri yoksa yerel analiz motoru devreye girer.
          </p>
        </div>
      )}

      {provider === "local" && (
        <p className="rounded-lg border border-line bg-panel2 px-3 py-2 text-xs text-muted">
          Yerel motor çevrimdışı çalışır ve deterministik analiz üretir; ancak
          LLM kadar ayrıntılı açıklama/sömürü senaryosu yazamaz.
        </p>
      )}

      {error && (
        <p className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-400">
          {error}
        </p>
      )}

      {testResult && (
        <p
          className={
            testResult.ok
              ? "rounded-lg border border-neon-dim/40 bg-neon/5 px-3 py-2 text-sm text-neon"
              : "rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-400"
          }
        >
          {testResult.ok ? "✓ " : "✕ "}
          {testResult.message}
        </p>
      )}

      <div className="flex items-center justify-end gap-2 pt-1">
        {saved && (
          <span className="flex items-center gap-1 text-xs text-neon">
            <Check className="h-4 w-4" /> Kaydedildi
          </span>
        )}
        {provider !== "auto" && (
          <button
            onClick={testConnection}
            disabled={testing || saving}
            className="btn-ghost px-4 py-2 text-sm"
            title="Kayitli API anahtarini kullanarak deneme istegi gonderir"
          >
            {testing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Zap className="h-4 w-4 text-neon-dim" />
            )}
            Test Et
          </button>
        )}
        {provider !== "auto" && provider !== "local" && (
          <button onClick={save} disabled={saving} className="btn-neon px-4 py-2 text-sm">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : "Kaydet"}
          </button>
        )}
      </div>
    </div>
  );
}
