"use client";

import { useMemo, useState } from "react";
import type { Subdomain } from "@/lib/types";

interface Group {
  base: string;
  total: number;
  alive: number;
  hosts: Subdomain[];
}

function groupByBase(subdomains: Subdomain[]): Group[] {
  const map = new Map<string, Subdomain[]>();
  for (const sub of subdomains) {
    const labels = sub.subdomain.split(".");
    const base = labels.length >= 2 ? labels.slice(-2).join(".") : sub.subdomain;
    const list = map.get(base) ?? [];
    list.push(sub);
    map.set(base, list);
  }
  return [...map.entries()]
    .map(([base, hosts]) => ({
      base,
      hosts,
      total: hosts.length,
      alive: hosts.filter((h) => h.is_alive).length,
    }))
    .sort((a, b) => b.total - a.total || a.base.localeCompare(b.base));
}

/**
 * Dependency-free treemap: each registered domain is a vertical band whose
 * height is proportional to its host count, hosts are stacked inside.
 */
export function SubdomainTreemap({ subdomains }: { subdomains: Subdomain[] }) {
  const groups = useMemo(() => groupByBase(subdomains), [subdomains]);
  const [selected, setSelected] = useState<Subdomain | null>(null);
  const total = Math.max(
    1,
    groups.reduce((sum, g) => sum + g.total, 0)
  );

  let cursor = 0;
  const bands = groups.map((group) => {
    const height = (group.total / total) * 100;
    const band = { group, y: cursor, height };
    cursor += height;
    return band;
  });

  return (
    <div className="space-y-2">
      <div className="overflow-hidden rounded-lg border border-line bg-black/60">
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-56 w-full">
          {bands.map(({ group, y, height }) => {
            let inner = y;
            const rows = group.hosts.map((host) => {
              const h = (1 / total) * 100;
              const row = { host, y: inner, h };
              inner += h;
              return row;
            });
            const ratio = Math.round((group.alive / group.total) * 100);
            return (
              <g key={group.base}>
                {rows.map(({ host, y: ry, h }) => (
                  <rect
                    key={host.subdomain}
                    x="0"
                    y={ry}
                    width="100"
                    height={Math.max(h - 0.15, 0.4)}
                    fill={host.is_alive ? "#00b32d" : "#3f3f46"}
                    opacity={host.is_alive ? 0.35 + 0.55 * (ratio / 100) : 0.5}
                    stroke="#0a0a0a"
                    strokeWidth={0.1}
                    className="cursor-pointer transition hover:opacity-100"
                    onClick={() => setSelected(host)}
                  >
                    <title>
                      {host.subdomain}
                      {host.status_code ? ` · ${host.status_code}` : ""}
                    </title>
                  </rect>
                ))}
              </g>
            );
          })}
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-[10px] text-muted">
        <span className="flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-sm bg-[#00b32d]/80" /> canlı
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-sm bg-zinc-600" /> ölü
        </span>
        <span>
          {groups.length} domain · {subdomains.length} host
        </span>
      </div>
      {selected && (
        <div className="rounded-lg border border-neon-dark bg-black/50 p-2.5 text-xs">
          <p className="font-mono text-neon">{selected.subdomain}</p>
          <p className="mt-0.5 text-muted">
            {selected.is_alive ? "canlı" : "ölü"}
            {selected.status_code ? ` · HTTP ${selected.status_code}` : ""}
            {selected.title ? ` · ${selected.title}` : ""}
          </p>
          {selected.technologies?.length ? (
            <div className="mt-1 flex flex-wrap gap-1">
              {selected.technologies.slice(0, 5).map((t) => (
                <span
                  key={t}
                  className="rounded border border-line bg-black/60 px-1 py-0.5 text-[10px] text-neon-dim"
                >
                  {t}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
