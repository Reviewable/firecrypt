module.exports = {
  env: {
    node: true,
    browser: true
  },
  parserOptions: {
    ecmaVersion: 6,
    sourceType: 'module'
  },
  globals: {
    Promise: false,
    LRUCache: true,
    CryptoJS: true
  },
  extends: ['../.eslintrc.js'],
};
