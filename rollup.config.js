import path from 'path';
import minify from 'rollup-plugin-minify-es';

const sharedConfig = {
  input: 'src/firecrypt.js',
  external: [
    'fflate',
    'lru-cache',
    'crypto-js',
    'cryptojs-extension',
  ],
};

const nodeConfig = {...sharedConfig};
nodeConfig.output = {
  file: path.resolve(import.meta.dirname, 'dist/node/firecrypt.js'),
  name: 'firecrypt',
  format: 'cjs',
  sourcemap: true,
};

const unminifiedBrowserConfig = {
  ...sharedConfig
};
unminifiedBrowserConfig.output = {
  file: path.resolve(import.meta.dirname, 'dist/browser/firecrypt.js'),
  name: 'firecrypt',
  format: 'iife',
  sourcemap: true,
};

const minifiedBrowserConfig = {
  plugins: [
    minify()
  ],
  ...sharedConfig
};
minifiedBrowserConfig.output = {
  file: path.resolve(import.meta.dirname, 'dist/browser/firecrypt.min.js'),
  name: 'firecrypt',
  format: 'iife',
  sourcemap: true,
};

export default [
  unminifiedBrowserConfig,
  minifiedBrowserConfig,
  nodeConfig,
];
