import { defineConfig } from 'vite';
import solid from 'vite-plugin-solid';

export default defineConfig({
  plugins: [solid()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: process.env.TAURI_DEV_HOST || '0.0.0.0',
    watch: { ignored: ['**/src-tauri/**', '**/crates/**', '**/tauri-plugin-capture/**'] },
  },
  build: { target: 'es2022', sourcemap: false },
});
