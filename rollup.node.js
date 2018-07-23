import path from 'path';
import babel from 'rollup-plugin-babel';

export default {
  input: 'src/firecrypt.js',
  output: {
    file: 'firecrypt.js',
    format: 'cjs',
    dir: path.resolve(__dirname, 'dist'),
  },
  plugins: [
    babel({
      exclude: 'node_modules/**',
    }),
  ],
  external: [
    'firebase',
    'lru-cache',
    'cryptojs',
    'crypto-js',
    'firebase-childrenkeys',
  ],
};
