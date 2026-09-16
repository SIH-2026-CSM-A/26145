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
          bg: "#0b0f19",
          card: "#111827",
          border: "#1f2937",
          accent: "#3b82f6",
          text: "#f3f4f6",
          muted: "#9ca3af",
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#10b981",
        }
      }
    },
  },
  plugins: [],
}