/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "bg-base": "var(--bg-base)",
        "bg-surface": "var(--bg-surface)",
        "bg-card": "var(--bg-card)",
        "accent-violet": "var(--accent-violet)",
        "accent-teal": "var(--accent-teal)",
        "accent-red": "var(--accent-red)",
        "accent-amber": "var(--accent-amber)",
        "text-primary": "var(--text-primary)",
        "text-secondary": "var(--text-secondary)",
        border: "var(--border)"
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"]
      },
      boxShadow: {
        brand: "0 0 0 1px var(--border), 0 10px 30px rgba(0, 0, 0, 0.4)",
        glow: "0 0 24px -6px var(--glow-violet)",
        "glow-teal": "0 0 20px -8px var(--glow-teal)"
      },
      keyframes: {
        "mesh-drift": {
          "0%, 100%": { transform: "scale(1) translate(0, 0)", opacity: "1" },
          "50%": { transform: "scale(1.04) translate(1%, -0.5%)", opacity: "0.92" }
        },
        "pulse-soft": {
          "0%, 100%": { opacity: "0.55" },
          "50%": { opacity: "1" }
        },
      },
      animation: {
        "mesh-drift": "mesh-drift 22s ease-in-out infinite",
        "pulse-soft": "pulse-soft 2.8s ease-in-out infinite"
      }
    }
  },
  plugins: []
};

