/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "var(--soc-bg)",
          raised: "var(--soc-raised)",
          panel: "var(--soc-panel)",
          overlay: "var(--soc-overlay)",
          border: "var(--soc-border)",
          card: "var(--soc-card)",
          hover: "var(--soc-hover)",
          text: "var(--soc-text)",
          muted: "var(--soc-muted)",
          critical: "var(--soc-critical)",
          high: "var(--soc-high)",
          medium: "var(--soc-medium)",
          low: "var(--soc-low)",
          normal: "var(--soc-normal)",
          novel: "var(--soc-novel)",
        }
      },
      fontFamily: {
        sans: ["Urbanist Variable", "sans-serif"],
        display: ["Urbanist Variable", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      borderRadius: {
        soc: "var(--soc-radius-md)",
        "soc-lg": "var(--soc-radius-lg)",
      },
      boxShadow: {
        "soc-panel": "var(--soc-shadow-panel)",
        "soc-critical": "var(--soc-shadow-critical)",
        "soc-high": "var(--soc-shadow-high)",
        "soc-medium": "var(--soc-shadow-medium)",
        "soc-low": "var(--soc-shadow-low)",
      },
      spacing: {
        "soc-page": "var(--soc-space-page)",
        "soc-card": "var(--soc-space-card)",
      },
    },
  },
  plugins: [],
}

