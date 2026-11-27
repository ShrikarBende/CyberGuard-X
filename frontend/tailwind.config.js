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
          50: "#12141C",
          100: "#12141C",
          200: "#333849",
          300: "#5B6072",
          400: "#6E7386",
          500: "#8A8FA3",
          600: "#A7ABBA",
          700: "#C6C9D4",
          800: "#E3E6EE",
          900: "#FFFFFF",
          950: "#F3F4F8",
        },
        soc: {
          bg: "var(--bg)", raised: "var(--chip)", panel: "var(--card)", overlay: "var(--card)",
          border: "var(--line)", card: "var(--card)", hover: "var(--chip)", text: "var(--ink)", muted: "var(--muted)",
          critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", normal: "var(--normal)", novel: "var(--novel)", accent: "var(--cobalt)",
          cobalt: "var(--cobalt)", chip: "var(--chip)", line: "var(--line)", ink: "var(--ink)", subtle: "var(--subtle)",
        }
      },
      fontFamily: {
        sans: ["Hanken Grotesk", "Hanken Grotesk Variable", "sans-serif"],
        display: ["Hanken Grotesk", "Hanken Grotesk Variable", "sans-serif"],
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

