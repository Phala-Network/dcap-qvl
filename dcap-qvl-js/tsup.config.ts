import { defineConfig } from 'tsup';

export default defineConfig([
  // Main entry (universal)
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: false,
    treeshake: true,
  },
  // Web-specific entry
  {
    entry: ['src/web.ts'],
    format: ['esm'],
    dts: true,
    sourcemap: true,
    platform: 'browser',
    splitting: false,
    treeshake: true,
  },
  // Node-specific entry
  {
    entry: ['src/node.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    platform: 'node',
    splitting: false,
    treeshake: true,
  },
]);
