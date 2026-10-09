/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#050b16",      // page background
        panel: "#0a1628",    // sidebar / cards
        node: "#072a4d",     // raised surfaces (matches the pipeline diagram)
        edge: "#1b3a5f",     // borders
        text: "#cfe3fb",
        mute: "#8aa4c4",
        accent: "#5aa9ff",
      },
      fontFamily: { sans: ['"IBM Plex Sans"', "system-ui", "Segoe UI", "sans-serif"] },
    },
  },
  plugins: [],
};
