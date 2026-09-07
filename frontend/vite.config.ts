import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiOrigin = process.env.ATKBRAIN_API_ORIGIN || "http://127.0.0.1:5003";
const frontendPort = Number(process.env.ATKBRAIN_FRONTEND_PORT || 5001);

// 开发期把 /api 与 /ws 代理到后端 FastAPI
export default defineConfig({
  plugins: [react()],
  server: {
    // 允许局域网访问（Windows 远程连 Kali 时用 192.168.x.x:5001）
    host: "0.0.0.0",
    port: frontendPort,
    strictPort: true,
    allowedHosts: true,
    proxy: {
      "/api": {
        target: apiOrigin,
        changeOrigin: true,
        ws: true,
        timeout: 0,
        proxyTimeout: 0,
        configure: (proxy) => {
          proxy.on("proxyReqWs", (_proxyReq, _req, socket) => {
            socket.setKeepAlive(true, 10000);
            socket.setNoDelay(true);
          });
          proxy.on("error", () => {});
        },
      },
    },
  },
  build: {
    outDir: "dist",
  },
});
