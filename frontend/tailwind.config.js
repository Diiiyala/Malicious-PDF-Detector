/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Surfaces
        ink: '#0d0d10',
        panel: '#16161a',
        // Brand — indigo / royal blue
        brand: {
          DEFAULT: '#4f46e5',
          300: '#818cf8',
          400: '#6366f1',
          500: '#4f46e5',
          600: '#4338ca',
        },
        // Secondary accent (indigo, for code/scripts)
        cyan: {
          glow: '#6366f1',
        },
        // Semantic
        safe: '#22c55e',
        warn: '#f59e0b',
        danger: '#f43f5e',
      },
      fontFamily: {
        sans: ["Tajawal", "system-ui", "sans-serif"],
        display: ["'Space Grotesk'", "Tajawal", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      backgroundImage: {
        'brand-gradient': 'linear-gradient(120deg, #4338ca 0%, #6366f1 100%)',
        'grid': 'linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
      },
      keyframes: {
        'fade-up': {
          '0%': { opacity: '0', transform: 'translateY(24px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        float: {
          '0%,100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-18px)' },
        },
        'pulse-glow': {
          '0%,100%': { opacity: '0.4' },
          '50%': { opacity: '0.9' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(900%)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        'spin-slow': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        'scan-beam': {
          '0%': { top: '6%', opacity: '0.4' },
          '50%': { opacity: '1' },
          '100%': { top: '90%', opacity: '0.4' },
        },
        blip: {
          '0%,100%': { opacity: '0.55', transform: 'scale(0.85)' },
          '50%': { opacity: '1', transform: 'scale(1.15)' },
        },
        'pop-in': {
          '0%': { opacity: '0', transform: 'scale(0) translateY(6px)' },
          '60%': { opacity: '1', transform: 'scale(1.15)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        'line-fill': {
          '0%': { width: '0%' },
          '100%': { width: '100%' },
        },
      },
      animation: {
        'fade-up': 'fade-up 0.7s cubic-bezier(0.16,1,0.3,1) both',
        'fade-in': 'fade-in 0.5s ease both',
        float: 'float 7s ease-in-out infinite',
        'pulse-glow': 'pulse-glow 4s ease-in-out infinite',
        scanline: 'scanline 2.2s linear infinite',
        shimmer: 'shimmer 2.5s linear infinite',
        'spin-slow': 'spin-slow 9s linear infinite',
        'scan-beam': 'scan-beam 2.8s ease-in-out infinite alternate',
        blip: 'blip 1.8s ease-in-out infinite',
        'pop-in': 'pop-in 0.5s cubic-bezier(0.16,1,0.3,1) both',
      },
    },
  },
  plugins: [],
}
