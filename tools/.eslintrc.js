'use strict';

module.exports = {
  env: {
    node: true
  },
  parserOptions: {
    ecmaVersion: 2018,
    sourceType: 'script'
  },
  plugins: ['lodash'],
  extends: ['../.eslintrc.js', 'plugin:lodash/canonical'],
  rules: {
    'lodash/chaining': ['error', 'implicit'],
    'lodash/prefer-filter': 'off',
    'lodash/prefer-invoke-map': 'off',
    'lodash/prop-shorthand': 'off',
    'lodash/matches-prop-shorthand': 'off',
    'lodash/prefer-immutable-method': 'off',
    'lodash/prefer-lodash-method': ['error', {ignoreMethods: ['split', 'replace']}],
    'lodash/prefer-map': 'off'
  }
};

