"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, KeyRound, Loader2, Settings2, X, Zap } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { ProviderInfo, SettingsState } from "@/lib/types";
import { cn } from "@/lib/utils";

export function AiProviderSelect({
  providers,
  value,
  onChange,
  disabled,
}: {
  providers: ProviderInfo[];
  value: string;
  onChange: (id: string) => void;
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className="input-neon w-full py-2 text-xs"
      title="AI saglayici"
    >
      <option value="auto">Otomatik (ilk yapılandırılan)</option>
      {providers.map((p) => (
        <option key={p.id} value={p.id}>
          {p.label}
          {p.configured ? " ✓" : ""}
        </option>
      ))}
    </select>
  );
}

export function AiSettingsModal({
  open,
  onClose,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  onSaved?: (provider: string) => void;
}) {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [provider, setProvider] = useState("auto");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
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
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Ayarlar yüklenemedi");
    }
  }, []);

  useEffect(() => {
    if (open) {
      setSaved(false);
      setTestResult(null);
      load();
    }
  }, [open, load]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

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
      });
      setSettings(updated);
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

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updateSettings({
        provider,
        model: model.trim() || undefined,
        base_url: baseUrl.trim() || undefined,
        api_key: apiKey.trim() || undefined,
      });
      setSettings(updated);
      setSaved(true);
      onSaved?.(provider);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Kaydedilemedi");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/75 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <div className="panel relative z-10 w-full max-w-lg p-5 shadow-glow animate-slide-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
            <Settings2 className="h-5 w-5 text-neon" /> AI Sağlayıcı Ayarları
          </h2>
          <button onClick={onClose} className="btn-ghost px-2 py-1" aria-label="Kapat">
            <X className="h-4 w-4" />
          </button>
        </div>

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
                    selectedCfg?.api_key_set
                      ? `Kayıtlı: ${selectedCfg.api_key} (değiştirmek için yeni girin)`
                      : "API anahtarinizi girin"
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
            <button onClick={onClose} className="btn-ghost px-4 py-2 text-sm">
              Vazgeç
            </button>
            <button onClick={save} disabled={saving} className="btn-neon px-4 py-2 text-sm">
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : "Kaydet"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
