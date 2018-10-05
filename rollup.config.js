import path from 'path';
import buble from 'rollup-plugin-buble';
import minify from 'rollup-plugin-minify-es';

const sharedConfig = {
  input: 'src/firecrypt.js',
  external: [
    'lru-cache',
    'crypto-js',
    'cryptojs-extension',
  ],
};

const nodeConfig = {...sharedConfig};
nodeConfig.output = {
  dir: path.resolve(__dirname, 'dist/node'),
  file: 'firecrypt.js',
  name: 'FireCrypt',
  format: 'cjs',
  sourcemap: true,
};

const unminifiedBrowserConfig = {
  plugins: [
    buble({transforms: {dangerousForOf: true}}),
  ],
  ...sharedConfig
};
unminifiedBrowserConfig.output = {
  dir: path.resolve(__dirname, 'dist/browser'),
  file: 'firecrypt.js',
  name: 'FireCrypt',
  format: 'iife',
  sourcemap: true,
};

const minifiedBrowserConfig = {
  plugins: [
    buble({transforms: {dangerousForOf: true}}),
    minify()
  ],
  ...sharedConfig
};
minifiedBrowserConfig.output = {
  dir: path.resolve(__dirname, 'dist/browser'),
  file: 'firecrypt.min.js',
  name: 'FireCrypt',
  format: 'iife',
  sourcemap: true,
};

export default [
  unminifiedBrowserConfig,
  minifiedBrowserConfig,
  nodeConfig,
];
