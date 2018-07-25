import path from 'path';
import babel from 'rollup-plugin-babel';
import minify from 'rollup-plugin-minify-es';

const sharedConfig = {
  input: 'src/firecrypt.js',
  plugins: [
    babel({
      exclude: 'node_modules/**',
    }),
  ],
  external: [
    'firebase',
    'lru-cache',
    'crypto-js',
    'cryptojs-extension',
    'firebase-childrenkeys',
  ],
};

const nodeConfig = {...sharedConfig};
nodeConfig.output = {
  dir: path.resolve(__dirname, 'dist/node'),
  file: 'firecrypt.js',
  format: 'cjs',
  sourcemap: true,
};

const unminifiedBrowserConfig = {...sharedConfig};
unminifiedBrowserConfig.output = {
  dir: path.resolve(__dirname, 'dist/browser'),
  file: 'firecrypt.js',
  format: 'iife',
  sourcemap: true,
};

const minifiedBrowserConfig = {...sharedConfig};
minifiedBrowserConfig.output = {
  dir: path.resolve(__dirname, 'dist/browser'),
  file: 'firecrypt.min.js',
  format: 'iife',
  sourcemap: true,
};
minifiedBrowserConfig.plugins = [...minifiedBrowserConfig.plugins, minify()];

export default [
  unminifiedBrowserConfig,
  minifiedBrowserConfig,
  nodeConfig,
];
