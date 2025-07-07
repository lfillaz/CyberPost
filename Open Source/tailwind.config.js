/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./public/index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber-dark': '#121212',
        'cyber-dark-light': '#1e1e1e',
        'cyber-green': '#00ff9d',
        'cyber-cyan': '#00e5ff',
        'cyber-red': '#ff3c5c',
        'cyber-purple': '#bd00ff',
      },
      fontFamily: {
        'code': ['JetBrains Mono', 'monospace'],
        'sans': ['Inter', 'Roboto', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'neon-green': '0 0 5px #00ff9d, 0 0 10px rgba(0, 255, 157, 0.5)',
        'neon-cyan': '0 0 5px #00e5ff, 0 0 10px rgba(0, 229, 255, 0.5)',
        'neon-red': '0 0 5px #ff3c5c, 0 0 10px rgba(255, 60, 92, 0.5)',
      },
      width: {
        'popup': '400px'
      },
      height: {
        'popup': '500px'
      }
    },
  },
  safelist: [
    'bg-cyber-dark',
    'bg-cyber-dark-light',
    'text-cyber-green',
    'border-cyber-green',
    'bg-cyber-green/20',
    'hover:bg-cyber-green/30',
  ],
  darkMode: 'class',
  plugins: [],
}
