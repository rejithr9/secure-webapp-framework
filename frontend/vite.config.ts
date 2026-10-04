import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Library build: React, the router and the WebAuthn helper stay external (installed by the app).
export default defineConfig({
  plugins: [react()],
  build: {
    lib: { entry: "src/index.ts", formats: ["es"], fileName: () => "swf-web.js", cssFileName: "swf-web" },
    emptyOutDir: false,
    sourcemap: true,
    rollupOptions: {
      external: ["react", "react-dom", "react/jsx-runtime", "react-router-dom", "@simplewebauthn/browser"],
    },
  },
});
