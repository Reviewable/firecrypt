if (typeof require !== 'undefined') {
  if (typeof LRUCache === 'undefined') global.LRUCache = require('lru-cache');
  if (typeof CryptoJS === 'undefined') global.CryptoJS = require('crypto-js/core');
  require('crypto-js/enc-base64');
  require('cryptojs-extension/build_node/siv');
}

CryptoJS.enc.Base64UrlSafe = {
  stringify: CryptoJS.enc.Base64.stringify,
  parse: CryptoJS.enc.Base64.parse,
  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
};

import * as crypto from './crypto';
import FireCryptReference from './FireCryptReference';

export default class FireCrypt {
  constructor(db, options = {}, specification = {}) {
    const dbIsNonNullObject = typeof db === 'object' && db !== null;
    if (!dbIsNonNullObject || typeof db.app !== 'object' || typeof db.ref !== 'function') {
      throw new Error(
        `Expected first argument passed to FireCrypt constructor to be a Firebase Database instance, 
        but got "${db}".`
      );
    } else if (typeof options !== 'object' || options === null) {
      throw new Error(
        `Expected second argument passed to FireCrypt constructor to be an object, but got "${options}".`
      );
    } else if (typeof specification !== 'object' || specification === null) {
      throw new Error(
        `Expected third argument passed to FireCrypt constructor to be an object, but got "${specification}".`
      );
    }

    this._db = db;

    options.cacheSize = options.cacheSize || 5 * 1000 * 1000;
    options.encryptionCacheSize = options.encryptionCacheSize || options.cacheSize;
    options.decryptionCacheSize = options.decryptionCacheSize || options.cacheSize;

    crypto.setStringEncryptionFunctions(crypto.throwNotSetUpError, crypto.throwNotSetUpError);

    if (typeof LRUCache === 'function') {
      crypto.setEncryptionCache(new LRUCache({
        max: options.encryptionCacheSize, length: crypto.computeCacheItemSize
      }));
      crypto.setDecryptionCache(new LRUCache({
        max: options.decryptionCacheSize, length: crypto.computeCacheItemSize
      }));
    }

    switch (options.algorithm) {
      case 'aes-siv':
        if (!options.key) throw new Error('You must specify a key to use AES encryption.');
        this.encryptionKeyCheckValue = setupAesSiv(options.key, options.keyCheckValue);
        break;
      case 'passthrough':
        crypto.setStringEncryptionFunctions((str) => str, (str) => str);
        break;
      case 'none':
        break;
      default:
        throw new Error('Unknown encryption algorithm "' + options.algorithm + '".');
    }

    crypto.setSpec(specification);

    return () => {
      return this;
    };
  }

  get app() {
    return this._db.app;
  }

  goOnline() {
    return this._db.goOnline();
  }

  goOffline() {
    return this._db.goOffline();
  }

  ref(path) {
    if (typeof path !== 'undefined' && typeof path !== 'string') {
      throw new Error(
        `Expected first argument passed to ref() to be undefined or a string, but got "${path}".`
      );
    }

    return new FireCryptReference(this._db.ref(path));
  }

  refFromURL(url) {
    if (typeof url !== 'string' || url.match(/^https:\/\/.*/g) === null) {
      throw new Error(
        `Expected first argument passed to refFromURL() to be a string URL, but got "${url}".`
      );
    }

    return new FireCryptReference(this._db.refFromURL(path));
  }
}

function setupAesSiv(key, checkValue) {
  const siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
  const encryptString = (str) => {
    return CryptoJS.enc.Base64UrlSafe.stringify(siv.encrypt(str));
  };
  const decryptString = (str) => {
    const result = siv.decrypt(CryptoJS.enc.Base64UrlSafe.parse(str));
    if (result === false) {
      const e = new Error('Wrong decryption key');
      e.firecrypt = 'WRONG_KEY';
      throw e;
    }
    return CryptoJS.enc.Utf8.stringify(result);
  };

  crypto.setStringEncryptionFunctions(encryptString, decryptString);

  if (checkValue) decryptString(checkValue);
  return encryptString(CryptoJS.enc.Base64UrlSafe.stringify(CryptoJS.lib.WordArray.random(10)));
}
