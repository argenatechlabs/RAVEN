"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { ScanLog } from "./types";

export type LogTransport = "sse" | "polling" | "idle";

const MAX_LOGS = 800;

/**
 * Streams live scan logs.
 *
 * Uses Server-Sent Events (which traverse ordinary HTTP proxies such as the
 * Next.js rewrite) and automatically falls back to polling when the event
 * stream cannot be established — so the terminal keeps working in every
 * deployment shape.
 */
export function useLiveLogs(scanId: string, active: boolean) {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [transport, setTransport] = useState<LogTransport>("idle");
  const lastId = useRef(0);
  const sourceRef = useRef<EventSource | null>(null);

  const append = useCallback((items: ScanLog[]) => {
    if (!items.length) return;
    lastId.current = Math.max(lastId.current, ...items.map((l) => l.id));
    setLogs((prev) => {
      const known = new Set(prev.map((l) => l.id));
      const fresh = items.filter((l) => !known.has(l.id));
      if (!fresh.length) return prev;
      return [...prev, ...fresh].slice(-MAX_LOGS);
    });
  }, []);

  const fetchPage = useCallback(async () => {
    try {
      const res = await api.getLogs(scanId, lastId.current, 300);
      if (res.items.length) append(res.items);
    } catch {
      /* bağlantı yoksa sessizce geç */
    }
  }, [scanId, append]);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const startPolling = () => {
      if (pollTimer || cancelled) return;
      setTransport("polling");
      pollTimer = setInterval(fetchPage, 2000);
    };

    const stopPolling = () => {
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = null;
    };

    // 1) Geçmiş logları yükle.
    (async () => {
      await fetchPage();
      if (cancelled || !active) {
        if (!active) setTransport("idle");
        return;
      }
      // 2) SSE dene; açılamazsa yoklamaya geç.
      if (typeof window === "undefined" || !window.EventSource) {
        startPolling();
        return;
      }
      let source: EventSource;
      try {
        source = new EventSource(`/api/scans/${scanId}/events`);
      } catch {
        startPolling();
        return;
      }
      sourceRef.current = source;
      let opened = false;
      source.onopen = () => {
        opened = true;
        stopPolling();
        setTransport("sse");
      };
      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload?.type === "log" && payload.log) {
            append([payload.log as ScanLog]);
          }
        } catch {
          /* bozuk kare */
        }
      };
      source.onerror = () => {
        source.close();
        sourceRef.current = null;
        if (!opened) startPolling();
      };
    })();

    return () => {
      cancelled = true;
      stopPolling();
      sourceRef.current?.close();
      sourceRef.current = null;
    };
  }, [scanId, active, fetchPage, append]);

  return { logs, transport, lastId };
}
