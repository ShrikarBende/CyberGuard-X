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
          bg: "#0A0F1D",
          panel: "#10182E",
          border: "#1E293B",
          card: "#131D38",
          hover: "#1A2649",
          text: "#F8FAFC",
          muted: "#94A3B8",
          critical: "#EF4444",
          high: "#F97316",
          medium: "#F59E0B",
          low: "#3B82F6",
          normal: "#10B981",
          novel: "#A855F7",
        }
      }
    },
  },
  plugins: [],
}

