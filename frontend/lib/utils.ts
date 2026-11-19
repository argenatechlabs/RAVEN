import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-950/60 text-red-400 border-red-800",
  high: "bg-orange-950/60 text-orange-400 border-orange-800",
  medium: "bg-yellow-950/60 text-yellow-400 border-yellow-800",
  low: "bg-green-950/60 text-green-400 border-green-800",
  info: "bg-zinc-800/60 text-zinc-400 border-zinc-700",
};

export const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-green-500",
  info: "bg-zinc-500",
};

export const STATUS_STYLE: Record<string, string> = {
  queued: "bg-zinc-800/70 text-zinc-300 border-zinc-700",
  scanning: "bg-neon-dark/40 text-neon border-neon-dim animate-pulse-neon",
  completed: "bg-green-950/60 text-green-400 border-green-800",
  failed: "bg-red-950/60 text-red-400 border-red-800",
};

export function formatDate(value?: string | null): string {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString("tr-TR", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return value;
  }
}

export function formatTime(value?: string | null): string {
  if (!value) return "--:--:--";
  try {
    return new Date(value).toLocaleTimeString("tr-TR");
  } catch {
    return value;
  }
}
