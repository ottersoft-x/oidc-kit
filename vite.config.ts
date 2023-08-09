import { defineConfig } from "vite";
import dts from "vite-plugin-dts";

export default defineConfig({
  build: {
    lib: {
      entry: "main.ts",
      fileName: "main",
      formats: ["es"],
    },
    rollupOptions: {
      external: ["oidc-client-ts"],
    },
  },
  plugins: [dts({ include: ["main.ts"] })],
});
