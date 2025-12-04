import globals from 'globals';
import reviewableConfigBaseline from 'reviewable-configs/eslint-config/baseline.js';

const BUILD_SCRIPTS = ['rollup.config.js'];
const LIBRARY_SCRIPTS = [...BUILD_SCRIPTS, 'eslint.config.mjs'];

export default [
  ...reviewableConfigBaseline,
  {
    ignores: ['node_modules/**', 'dist/**']
  },
  {
    ignores: LIBRARY_SCRIPTS,
    languageOptions: {
      globals: {
        ...globals['shared-node-browser'],
        ...globals.es2017,
        CryptoJS: false,
        fflate: false,
        LRUCache: false,
      },
      ecmaVersion: 2019,
      sourceType: 'module',
    },
    rules: {
      'import/no-cycle': 'off',
    },
  },
  {
    files: ['tools/*.js'],
    languageOptions: {
      globals: globals.node,
      ecmaVersion: 2024,
      sourceType: 'commonjs'
    }
  },
  {
    files: BUILD_SCRIPTS,
    languageOptions: {
      globals: globals.node,
      ecmaVersion: 2024,
      sourceType: 'module',
    },
  },
];
