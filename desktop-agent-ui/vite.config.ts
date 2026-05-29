import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  base: "./",
  clearScreen: false,
  plugins: [vue()],
  server: {
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"]
    }
  }
});
