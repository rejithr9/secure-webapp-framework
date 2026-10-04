import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // One copy of React even though @swf/web is linked from a local folder.
  resolve: { dedupe: ["react", "react-dom", "react-router-dom"] },
  server: { port: 5174, strictPort: true, proxy: { "/api": "http://127.0.0.1:8001" } },
});
