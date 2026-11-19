"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronRight, Globe, GlobeLock, Server } from "lucide-react";
import type { Subdomain } from "@/lib/types";
import { cn } from "@/lib/utils";

interface TreeNode {
  label: string;
  full: string;
  children: Map<string, TreeNode>;
  sub?: Subdomain;
}

function ensureChild(node: TreeNode, part: string, full: string): TreeNode {
  if (!node.children.has(part)) {
    node.children.set(part, { label: part, full, children: new Map() });
  }
  return node.children.get(part)!;
}

/** Build a natural tree: registered domain at the top, subdomains below. */
function buildTree(subdomains: Subdomain[]): TreeNode {
  const root: TreeNode = { label: "", full: "", children: new Map() };
  for (const sub of subdomains) {
    const labels = sub.subdomain.split(".");
    const base = labels.length >= 2 ? labels.slice(-2).join(".") : sub.subdomain;
    const prefix = labels.length >= 2 ? labels.slice(0, -2) : [];
    const baseNode = ensureChild(root, base, base);
    let node = baseNode;
    let full = base;
    for (const part of prefix) {
      full = `${part}.${full}`;
      node = ensureChild(node, part, full);
    }
    node.sub = sub;
    node.full = sub.subdomain;
  }
  return root;
}

function Node({
  node,
  depth,
  expanded,
  toggle,
}: {
  node: TreeNode;
  depth: number;
  expanded: Set<string>;
  toggle: (key: string) => void;
}) {
  const key = node.full || "__root__";
  const hasChildren = node.children.size > 0;
  const isOpen = expanded.has(key);
  const alive = node.sub?.is_alive;
  const techs = node.sub?.technologies ?? [];

  return (
    <li>
      <div
        className={cn(
          "flex items-center gap-1.5 rounded px-1.5 py-1 text-xs hover:bg-panel2",
          node.sub ? "cursor-pointer" : "cursor-default"
        )}
        style={{ paddingLeft: `${depth * 14 + 6}px` }}
        onClick={() => hasChildren && toggle(key)}
      >
        {hasChildren ? (
          <ChevronRight
            className={cn("h-3 w-3 shrink-0 text-muted transition", isOpen && "rotate-90")}
          />
        ) : (
          <span className="w-3 shrink-0" />
        )}
        {node.sub ? (
          alive ? (
            <Globe className="h-3.5 w-3.5 shrink-0 text-neon" />
          ) : (
            <GlobeLock className="h-3.5 w-3.5 shrink-0 text-zinc-600" />
          )
        ) : (
          <Server className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
        )}
        <span className={cn("truncate font-mono", alive ? "text-zinc-200" : "text-zinc-500")}>
          {node.label}
        </span>
        {node.sub?.status_code && (
          <span className="ml-auto text-[10px] text-muted">{node.sub.status_code}</span>
        )}
      </div>
      {hasChildren && isOpen && (
        <ul>
          {[...node.children.values()].map((child) => (
            <Node
              key={child.full}
              node={child}
              depth={depth + 1}
              expanded={expanded}
              toggle={toggle}
            />
          ))}
        </ul>
      )}
      {node.sub && isOpen && techs.length > 0 && (
        <div
          className="mb-1 flex flex-wrap gap-1 pl-8 pr-2"
          style={{ marginLeft: `${depth * 14}px` }}
        >
          {techs.slice(0, 6).map((t) => (
            <span
              key={t}
              className="rounded border border-line bg-black/50 px-1.5 py-0.5 text-[10px] text-neon-dim"
            >
              {t}
            </span>
          ))}
        </div>
      )}
    </li>
  );
}

export function SubdomainTree({ subdomains }: { subdomains: Subdomain[] }) {
  const tree = useMemo(() => buildTree(subdomains), [subdomains]);
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(["__root__", ...tree.children.keys()])
  );
  const didInit = useRef(false);

  // Auto-expand the registered-domain level the first time data arrives.
  useEffect(() => {
    if (didInit.current || subdomains.length === 0) return;
    didInit.current = true;
    setExpanded((prev) => new Set([...prev, ...tree.children.keys()]));
  }, [subdomains.length, tree]);

  const toggle = (key: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const alive = subdomains.filter((s) => s.is_alive).length;

  return (
    <div className="panel flex h-full min-h-[320px] flex-col overflow-hidden">
      <div className="border-b border-line px-3 py-2">
        <span className="label-neon">Alt Alan Ağacı</span>
        <span className="ml-2 text-[10px] text-muted">
          {alive}/{subdomains.length} canlı
        </span>
      </div>
      <div className="flex-1 overflow-y-auto p-2">
        {subdomains.length === 0 ? (
          <p className="p-3 text-xs text-muted">Henüz subdomain yok.</p>
        ) : (
          <ul>
            {[...tree.children.values()].map((child) => (
              <Node
                key={child.full || "__root__"}
                node={child}
                depth={0}
                expanded={expanded}
                toggle={toggle}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
