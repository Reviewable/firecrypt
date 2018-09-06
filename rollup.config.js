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

const unminifiedBrowserConfig = {...sharedConfig};
unminifiedBrowserConfig.output = {
  dir: path.resolve(__dirname, 'dist/browser'),
  file: 'firecrypt.js',
  name: 'FireCrypt',
  format: 'iife',
  sourcemap: true,
};

const minifiedBrowserConfig = {...sharedConfig};
minifiedBrowserConfig.output = {
  dir: path.resolve(__dirname, 'dist/browser'),
  file: 'firecrypt.min.js',
  name: 'FireCrypt',
  format: 'iife',
  sourcemap: true,
};
minifiedBrowserConfig.plugins = [...minifiedBrowserConfig.plugins, minify()];

export default [
  unminifiedBrowserConfig,
  minifiedBrowserConfig,
  nodeConfig,
];
