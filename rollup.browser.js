import path from 'path';
import babel from 'rollup-plugin-babel';
import minify from 'rollup-plugin-minify-es';

export default {
  input: 'src/firecrypt.js',
  output: {
    file: 'firecrypt.min.js',
    format: 'iife',
    dir: path.resolve(__dirname, 'dist'),
  },
  plugins: [
    babel({
      exclude: 'node_modules/**',
    }),
    minify(),
  ],
  external: [
    'firebase',
    'lru-cache',
    'cryptojs',
    'crypto-js',
    'firebase-childrenkeys',
  ],
};
