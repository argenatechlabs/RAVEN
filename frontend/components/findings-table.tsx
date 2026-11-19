"use client";

import { useMemo, useState } from "react";
import { Bug, Search, ShieldOff } from "lucide-react";
import type { Finding, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";
import { EmptyState, SeverityBadge } from "./ui";

const FILTERS: Array<{ key: Severity | "all"; label: string }> = [
  { key: "all", label: "Tümü" },
  { key: "critical", label: "Kritik" },
  { key: "high", label: "Yüksek" },
  { key: "medium", label: "Orta" },
  { key: "low", label: "Düşük" },
];

export function FindingsTable({
  findings,
  onSelect,
}: {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
}) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");
  const [showFp, setShowFp] = useState(false);

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (f.is_false_positive && !showFp) continue;
      c.all += 1;
      c[f.severity] = (c[f.severity] || 0) + 1;
    }
    return c;
  }, [findings, showFp]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (f.is_false_positive && !showFp) return false;
      if (filter !== "all" && f.severity !== filter) return false;
      if (q && !(`${f.title} ${f.url || ""}`.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [findings, filter, query, showFp]);

  return (
    <div className="panel flex h-full flex-col overflow-hidden">
      <div className="space-y-3 border-b border-line p-3">
        <div className="flex items-center justify-between">
          <span className="label-neon">Bulgular</span>
          <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-muted">
            <input
              type="checkbox"
              checked={showFp}
              onChange={(e) => setShowFp(e.target.checked)}
              className="h-3.5 w-3.5 accent-[#00ff41]"
            />
            <ShieldOff className="h-3.5 w-3.5" />
            False positive
          </label>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={cn(
                "rounded-md border px-2.5 py-1 text-[11px] font-medium transition",
                filter === f.key
                  ? "border-neon-dim bg-neon-dark/40 text-neon"
                  : "border-line bg-black/40 text-zinc-400 hover:border-neon-dim hover:text-neon"
              )}
            >
              {f.label}
              <span className="ml-1 text-[10px] opacity-70">{counts[f.key] || 0}</span>
            </button>
          ))}
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Bulgu veya URL ara…"
            className="input-neon py-2 pl-9 text-sm"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {rows.length === 0 ? (
          <EmptyState
            icon={<Bug className="h-8 w-8" />}
            title="Bulgu yok"
            hint="Filtreyi değiştirin veya taramanın bitmesini bekleyin"
          />
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 bg-panel">
              <tr className="border-b border-line text-[11px] uppercase tracking-wider text-muted">
                <th className="px-3 py-2">Seviye</th>
                <th className="px-3 py-2">Bulgu</th>
                <th className="px-3 py-2 text-right">CVSS</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => onSelect(f)}
                  className="cursor-pointer border-b border-line/60 transition hover:bg-neon-dark/20"
                >
                  <td className="px-3 py-2.5">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="max-w-0 px-3 py-2.5">
                    <p className="truncate text-zinc-200">{f.title}</p>
                    <p className="truncate font-mono text-[11px] text-muted">{f.url}</p>
                  </td>
                  <td className="px-3 py-2.5 text-right font-mono text-zinc-300">
                    {f.cvss ?? "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
