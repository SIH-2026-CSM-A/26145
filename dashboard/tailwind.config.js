/** @type {import('tailwindcss').Config} */
// Design tokens live in src/index.css (:root); Tailwind only names them.
const v = (n) => `rgb(var(--${n}) / <alpha-value>)`;
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: v('ink'), deep: v('deep'), panel: v('panel'), line: v('line'),
        fg: v('fg'), dim: v('dim'), faint: v('faint'), safe: v('safe'), brand: v('brand'),
      },
      fontFamily: {
        sans: ['"Space Grotesk Variable"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', 'ui-monospace', 'monospace'],
      },
      fontSize: { xs: ['0.875rem', '1.25rem'] }, // 14 px floor: nothing on screen is smaller
    },
  },
  plugins: [],
};
