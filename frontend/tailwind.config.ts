import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0a0a0a",
        panel: "#0f0f0f",
        panel2: "#141414",
        line: "#1f1f1f",
        neon: "#00ff41",
        "neon-dim": "#00b32d",
        "neon-dark": "#003b11",
        muted: "#6b7280",
        danger: "#dc2626",
        warn: "#ca8a04",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
        sans: ["ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 20px rgba(0,255,65,0.25)",
        "glow-sm": "0 0 10px rgba(0,255,65,0.2)",
      },
      keyframes: {
        blink: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0" } },
        pulseNeon: {
          "0%,100%": { opacity: "1" },
          "50%": { opacity: "0.55" },
        },
        slideIn: {
          from: { transform: "translateX(100%)" },
          to: { transform: "translateX(0)" },
        },
        fadeIn: { from: { opacity: "0" }, to: { opacity: "1" } },
      },
      animation: {
        blink: "blink 1s step-end infinite",
        "pulse-neon": "pulseNeon 2s ease-in-out infinite",
        "slide-in": "slideIn 0.22s ease-out",
        "fade-in": "fadeIn 0.2s ease-out",
      },
    },
  },
  plugins: [],
};

export default config;
