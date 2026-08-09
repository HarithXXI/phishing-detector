/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyan: {
          400: '#38bdf8',
          500: '#06b6d4',
          600: '#0891b2',
        },
        dark: {
          950: '#020617',
          900: '#0f172a',
          800: '#1e293b',
          700: '#334155',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
