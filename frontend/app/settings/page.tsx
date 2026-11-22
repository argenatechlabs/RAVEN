import type { Metadata } from "next";
import { SettingsClient } from "@/components/settings-client";

export const metadata: Metadata = {
  title: "Ayarlar — RAVEN",
  description: "AI sağlayıcılarını ve API anahtarlarını yönet.",
};

export default function SettingsPage() {
  return <SettingsClient />;
}
