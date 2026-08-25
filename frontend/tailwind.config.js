/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Application base - dark professional surface
        base: {
          950: '#0a0e14',
          900: '#0d1219',
          850: '#111826',
          800: '#151d2d',
          700: '#1c2638',
          600: '#243046',
          500: '#33405c',
          400: '#4a5876',
          300: '#64748b',
        },
        // Primary accent - restrained cyan/blue
        accent: {
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
        },
        // Security severity palette (single source of truth)
        security: {
          critical: '#ef4444',
          'critical-bg': 'rgba(239, 68, 68, 0.12)',
          high: '#f97316',
          'high-bg': 'rgba(249, 115, 22, 0.12)',
          medium: '#f59e0b',
          'medium-bg': 'rgba(245, 158, 11, 0.12)',
          low: '#38bdf8',
          'low-bg': 'rgba(56, 189, 248, 0.12)',
          pass: '#22c55e',
          'pass-bg': 'rgba(34, 197, 94, 0.12)',
          fail: '#ef4444',
          'fail-bg': 'rgba(239, 68, 68, 0.12)',
          review: '#f59e0b',
          'review-bg': 'rgba(245, 158, 11, 0.12)',
          unknown: '#94a3b8',
          'unknown-bg': 'rgba(148, 163, 184, 0.12)',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"SF Mono"', 'Menlo', 'Consolas', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '6px',
        lg: '8px',
        xl: '10px',
      },
      boxShadow: {
        panel: '0 1px 2px rgba(0,0,0,0.3), 0 1px 3px rgba(0,0,0,0.2)',
        'panel-lg': '0 4px 12px rgba(0,0,0,0.35)',
      },
    },
  },
  plugins: [],
}
