/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "rgb(var(--color-bg) / <alpha-value>)",
        panel: "rgb(var(--color-surface) / <alpha-value>)",
        node: "rgb(var(--color-raised) / <alpha-value>)",
        edge: "rgb(var(--color-border) / <alpha-value>)",
        text: "rgb(var(--color-text) / <alpha-value>)",
        mute: "rgb(var(--color-muted) / <alpha-value>)",
        accent: "rgb(var(--color-accent) / <alpha-value>)",
        brand: "rgb(var(--color-brand) / <alpha-value>)",
        "brand-hover": "rgb(var(--color-brand-hover) / <alpha-value>)",
        "table-head": "rgb(var(--color-table-head) / <alpha-value>)",
        "table-head-text": "rgb(var(--color-table-head-text) / <alpha-value>)",
        "table-hover": "rgb(var(--color-table-hover) / <alpha-value>)",
      },
      fontFamily: {
        sans: ['"DM Sans"', "sans-serif"],
        display: ['"Manrope"', "sans-serif"],
      },
    },
  },
  plugins: [],
};
