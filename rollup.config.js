import path from 'path';
import buble from '@rollup/plugin-buble';
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
  file: path.resolve(__dirname, 'dist/node/firecrypt.js'),
  name: 'firecrypt',
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
  file: path.resolve(__dirname, 'dist/browser/firecrypt.js'),
  name: 'firecrypt',
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
  file: path.resolve(__dirname, 'dist/browser/firecrypt.min.js'),
  name: 'firecrypt',
  format: 'iife',
  sourcemap: true,
};

export default [
  unminifiedBrowserConfig,
  minifiedBrowserConfig,
  nodeConfig,
];
