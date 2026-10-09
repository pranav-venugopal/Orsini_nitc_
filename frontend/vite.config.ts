import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
	plugins: [react()],
	publicDir: "../images",
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
