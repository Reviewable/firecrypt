module.exports = {
  env: {
    node: true,
    browser: true,
    es6: true
  },
  parserOptions: {
    ecmaVersion: 6,
    sourceType: 'module'
  },
  globals: {
    LRUCache: true,
    CryptoJS: true
  },
  extends: ['../.eslintrc.js'],
};
