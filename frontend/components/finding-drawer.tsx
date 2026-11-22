"use client";

import { useEffect } from "react";
import { Bot, Crosshair, FileCode2, ShieldOff, X } from "lucide-react";
import type { Finding } from "@/lib/types";
import { SeverityBadge } from "./ui";

function Block({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-widest text-neon">
        {icon}
        {title}
      </div>
      {children}
    </div>
  );
}

export function FindingDrawer({
  finding,
  onClose,
}: {
  finding: Finding | null;
  onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <aside className="relative z-10 h-full w-full max-w-xl overflow-y-auto border-l border-neon-dim bg-panel p-5 shadow-glow animate-slide-in">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              {finding.is_false_positive && (
                <span className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-800/60 px-2 py-0.5 text-[11px] font-semibold text-zinc-400">
                  <ShieldOff className="h-3 w-3" /> False Positive
                </span>
              )}
              <span className="rounded-md border border-line bg-black/50 px-2 py-0.5 text-[11px] text-muted">
                {finding.type}
              </span>
            </div>
            <h2 className="text-lg font-semibold text-zinc-100">{finding.title}</h2>
          </div>
          <button onClick={onClose} className="btn-ghost px-2 py-1" aria-label="Kapat">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mb-4 grid grid-cols-3 gap-2 text-center">
          <div className="rounded-lg border border-line bg-black/40 p-2">
            <p className="text-[10px] uppercase tracking-widest text-muted">CVSS</p>
            <p className="font-mono text-lg text-neon">{finding.cvss ?? "-"}</p>
          </div>
          <div className="col-span-2 rounded-lg border border-line bg-black/40 p-2">
            <p className="text-[10px] uppercase tracking-widest text-muted">OWASP</p>
            <p className="truncate font-mono text-xs text-zinc-300">
              {finding.owasp_category || "-"}
            </p>
          </div>
        </div>

        {finding.url && (
          <div className="mb-4">
            <p className="label-neon mb-1">URL</p>
            <p className="break-all rounded-lg border border-line bg-black/50 p-2 font-mono text-xs text-neon-dim">
              {finding.url}
            </p>
          </div>
        )}

        <p className="mb-4 text-xs text-muted">
          Doğrulama: {finding.verification === "unverified" || !finding.verification ? "manuel doğrulama gerekli" : finding.verification} · Analiz motoru: {finding.ai_provider || "bilinmiyor"} · AI güveni: {finding.ai_confidence != null ? `%${Math.round(finding.ai_confidence * 100)}` : "belirtilmedi"}. AI güveni, bulgunun doğrulandığı anlamına gelmez.
        </p>
        <div className="space-y-4">
          <Block title="AI Analizi" icon={<Bot className="h-4 w-4" />}>
            <p className="rounded-lg border border-line bg-black/40 p-3 text-sm leading-6 text-zinc-300">
              {finding.ai_analysis || "AI analizi henüz yok."}
            </p>
          </Block>

          <Block title="Sömürü Senaryosu" icon={<Crosshair className="h-4 w-4" />}>
            <p className="rounded-lg border border-line bg-black/40 p-3 text-sm leading-6 text-zinc-300">
              {finding.exploit_scenario || "Senaryo üretilemedi."}
            </p>
          </Block>

          {finding.evidence && (
            <Block title="Kanıt" icon={<FileCode2 className="h-4 w-4" />}>
              <pre className="max-h-56 overflow-auto rounded-lg border border-line bg-black/70 p-3 font-mono text-xs text-zinc-300">
                {finding.evidence}
              </pre>
            </Block>
          )}

          <Block title="Düzeltme / Fix" icon={<FileCode2 className="h-4 w-4" />}>
            <pre className="max-h-72 overflow-auto rounded-lg border border-neon-dark bg-black/70 p-3 font-mono text-xs text-neon">
              {finding.fix_code || "Düzeltme önerisi yok."}
            </pre>
          </Block>
        </div>
      </aside>
    </div>
  );
}
