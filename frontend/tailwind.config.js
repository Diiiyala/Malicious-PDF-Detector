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
        page: '#F2F2F2',
        ink: { DEFAULT: '#141414', 2: '#444444', 3: '#666666' },
        line: { DEFAULT: '#E0E0E0', 2: '#C6C6C6' },
        // Brand
        brand: {
          DEFAULT: '#5271FF',
          300: '#CBD4FF',
          400: '#5271FF',
          500: '#5271FF',
          600: '#3F5BE8',
          ink: '#3450D8',
          soft: '#EEF1FF',
          line: '#CBD4FF',
        },
        // Semantic
        safe: { DEFAULT: '#136B41', bg: '#E1F4EA', dot: '#22A466' },
        warn: { DEFAULT: '#7F5A00', bg: '#FFF3D1', dot: '#E3A600' },
        danger: { DEFAULT: '#B92626', bg: '#FCE9E9', dot: '#D33A3A' },
        orange: { DEFAULT: '#B84A12', bg: '#FCEDE2', dot: '#E0641F' },
        info: { DEFAULT: '#245C9C', bg: '#E5EFFB', dot: '#3F82CC' },
      },
      fontFamily: {
        sans: ["Satoshi", "Tajawal", "system-ui", "sans-serif"],
        display: ["Satoshi", "Tajawal", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      backgroundImage: {
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
