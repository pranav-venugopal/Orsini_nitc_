import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
	plugins: [tailwindcss(), react()],
	publicDir: false,
	build: {
		rollupOptions: {
			output: {
				manualChunks(id) {
					if (id.includes("/node_modules/three/")) return "three";
					if (id.includes("/node_modules/three-stdlib/")) return "three-stdlib";
					if (id.includes("/node_modules/@react-three/")) return "react-three";
				},
			},
		},
	},
});
