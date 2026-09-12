import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// base must match the GitHub Pages sub-path:
// https://<user>.github.io/Shell-Master/
export default defineConfig({
  base: '/Shell-Master/',
  plugins: [react()],
});
