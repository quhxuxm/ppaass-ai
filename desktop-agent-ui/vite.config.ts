import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  base: "./",
  clearScreen: false,
  plugins: [vue()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) {
            return undefined;
          }
          if (id.includes("/vue/") || id.includes("@vue")) {
            return "vue";
          }
          if (id.includes("primevue") || id.includes("@primeuix") || id.includes("primeicons")) {
            return "primevue";
          }
          if (id.includes("@tauri-apps")) {
            return "tauri";
          }
          return "vendor";
        }
      }
    }
  },
  server: {
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"]
    }
  }
});
