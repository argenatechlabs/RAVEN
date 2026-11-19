import type { Metadata } from "next";
import Link from "next/link";
import { History, Radar, ShieldAlert } from "lucide-react";
import "./globals.css";

export const metadata: Metadata = {
  title: "RAVEN — Autonomous AI Pentester",
  description:
    "Domain gir, 5 dakikada otomatik sızma testi yap, AI analizi ve profesyonel PDF raporu al.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="tr">
      <body className="flex min-h-screen flex-col font-sans">
        <header className="sticky top-0 z-40 border-b border-line bg-ink/90 backdrop-blur">
          <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-3">
            <Link href="/" className="flex items-center gap-2">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-neon-dim bg-neon-dark/30 shadow-glow-sm">
                <Radar className="h-5 w-5 text-neon" />
              </span>
              <span className="text-xl font-bold tracking-[0.2em] text-neon neon-text">
                RAVEN
              </span>
            </Link>
            <nav className="ml-6 flex items-center gap-1 text-sm">
              <Link
                href="/"
                className="rounded-md px-3 py-1.5 text-zinc-300 transition hover:bg-panel2 hover:text-neon"
              >
                Tara
              </Link>
              <Link
                href="/history"
                className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-zinc-300 transition hover:bg-panel2 hover:text-neon"
              >
                <History className="h-4 w-4" /> Geçmiş
              </Link>
            </nav>
            <span className="ml-auto hidden items-center gap-1.5 text-[11px] text-muted sm:flex">
              <ShieldAlert className="h-3.5 w-3.5 text-neon-dim" />
              Yalnızca yetkili hedeflerde kullanın
            </span>
          </div>
        </header>

        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">{children}</main>

        <footer className="border-t border-line py-4">
          <p className="mx-auto max-w-7xl px-4 text-[11px] leading-5 text-muted">
            RAVEN, izinsiz hedeflere tarama yapmayı onaylamaz. Tüm bulgular yalnızca
            savunma amaçlıdır. Kullanım, hedef sistem sahibinin yazılı iznini taşımak
            zorundadır. Bu araç yalnızca yetkili güvenlik testleri içindir.
          </p>
        </footer>
      </body>
    </html>
  );
}
