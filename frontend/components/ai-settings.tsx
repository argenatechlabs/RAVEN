"use client";

import { useCallback, useEffect, useState } from "react";
import { Settings2, X } from "lucide-react";
import type { ProviderInfo } from "@/lib/types";
import { ProviderSettingsForm } from "./provider-settings-form";

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

/** Compact modal version of the provider editor (used on the dashboard). */
export function AiSettingsModal({
  open,
  onClose,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  onSaved?: (provider: string) => void;
}) {
  const [reloadKey, setReloadKey] = useState(0);

  const handleSaved = useCallback(
    (provider: string) => {
      onSaved?.(provider);
      setReloadKey((k) => k + 1);
    },
    [onSaved],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/75 backdrop-blur-sm animate-fade-in"
        onClick={onClose}
      />
      <div className="panel relative z-10 max-h-[90vh] w-full max-w-lg overflow-y-auto p-5 shadow-glow animate-slide-in">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
            <Settings2 className="h-5 w-5 text-neon" /> AI Sağlayıcı Ayarları
          </h2>
          <button onClick={onClose} className="btn-ghost px-2 py-1" aria-label="Kapat">
            <X className="h-4 w-4" />
          </button>
        </div>
        <ProviderSettingsForm key={reloadKey} onSaved={handleSaved} />
      </div>
    </div>
  );
}
