/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: '#0D1117',
          card: '#161B22',
          hover: '#1C2333',
          border: '#30363D'
        },
        phantom: {
          red: '#FF3333',
          magenta: '#BD34FE',
          cyan: '#58A6FF',
          green: '#3FB950',
          yellow: '#D29922',
          error: '#F85149'
        },
        text: {
          primary: '#E6EDF3',
          secondary: '#8B949E',
          dim: '#484F58'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    }
  },
  plugins: []
}