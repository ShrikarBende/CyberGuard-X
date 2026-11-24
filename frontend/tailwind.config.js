/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          50: "#f8f8f8",
          100: "#f4f4f4",
          200: "#e5e5e5",
          300: "#d4d4d4",
          400: "#a3a3a3",
          500: "#737373",
          600: "#525252",
          700: "#404040",
          800: "#272727",
          900: "#181818",
          950: "#131209",
        },
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
          accent: "var(--soc-accent)",
        }
      },
      fontFamily: {
        sans: ["Manrope Variable", "sans-serif"],
        display: ["Manrope Variable", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      spacing: {
        "1.5": "0.5rem",
        "2.5": "0.75rem",
        "3.5": "1rem",
        "5": "1rem",
        "7": "1.5rem",
        "9": "2rem",
        "11": "2.5rem",
        "14": "3rem",
        "18": "4rem",
        "22": "5rem",
        "28": "6rem",
      },
      zIndex: {
        60: "60",
        80: "80",
        100: "100",
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

