"use client";

import { useEffect, useRef } from "react";
import { TerminalSquare } from "lucide-react";
import type { ScanLog } from "@/lib/types";
import type { LogTransport } from "@/lib/use-live-logs";
import { cn, formatTime } from "@/lib/utils";

const LEVEL_CLASS: Record<string, string> = {
  info: "text-zinc-400",
  debug: "text-zinc-600",
  warning: "text-yellow-400",
  error: "text-red-400",
  success: "text-neon",
};

export function Terminal({
  logs,
  scanning,
  transport = "idle",
}: {
  logs: ScanLog[];
  scanning: boolean;
  transport?: LogTransport;
}) {
  const endRef = useRef<HTMLDivElement | null>(null);
  const boxRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const box = boxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [logs.length]);

  return (
    <div className="panel flex h-full min-h-[320px] flex-col overflow-hidden">
      <div className="flex items-center gap-2 border-b border-line px-3 py-2">
        <TerminalSquare className="h-4 w-4 text-neon" />
        <span className="label-neon">Canlı Log</span>
        <span
          className={cn(
            "ml-auto rounded border px-1.5 py-0.5 font-mono text-[10px]",
            transport === "sse"
              ? "border-neon-dim bg-neon-dark/30 text-neon"
              : transport === "polling"
                ? "border-yellow-900 bg-yellow-950/30 text-yellow-300"
                : "border-line text-zinc-500"
          )}
        >
          {transport === "sse" ? "SSE" : transport === "polling" ? "YOKLAMA" : "—"}
        </span>
        <span className="flex gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-yellow-500/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-green-500/70" />
        </span>
      </div>
      <div
        ref={boxRef}
        className="terminal flex-1 space-y-1 overflow-y-auto bg-black/60 p-3"
      >
        {logs.length === 0 && (
          <p className="text-zinc-600">$ raven scan --target …</p>
        )}
        {logs.map((log) => (
          <div key={log.id} className="flex gap-2">
            <span className="shrink-0 text-zinc-600">{formatTime(log.ts)}</span>
            <span
              className={cn(
                "shrink-0 font-bold uppercase",
                log.level === "success" ? "text-neon" : "text-zinc-500"
              )}
            >
              [{log.level}]
            </span>
            <span className={cn("break-all", LEVEL_CLASS[log.level] || "text-zinc-400")}>
              {log.message}
            </span>
          </div>
        ))}
        {scanning && <span className="ml-1 inline-block h-4 w-2 animate-blink bg-neon" />}
        <div ref={endRef} />
      </div>
    </div>
  );
}
