/**
 * VPN Sentinel — Deep Charcoal + Burnt Orange
 * Keep these hex values in sync with src/index.css :root tokens.
 */
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#121314',
        'bg-secondary': '#1A1C1E',
        accent: {
          DEFAULT: '#E05A26',
          hover: '#FF7A45',
        },
        'text-primary': '#F3F4F6',
        'text-muted': '#8C92AC',
        border: '#2D3139',
      },
    },
  },
}
