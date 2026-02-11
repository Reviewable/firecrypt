if (typeof require !== 'undefined') {
  /* eslint-disable no-undef */
  if (typeof fflate === 'undefined') global.fflate = require('fflate');
  if (typeof lrucache === 'undefined') global.lrucache = require('lru-cache');
  if (typeof CryptoJS === 'undefined') global.CryptoJS = require('crypto-js/core');
  require('crypto-js/lib-typedarrays');
  require('crypto-js/enc-base64');
  require('crypto-js/enc-base64url');
  require('cryptojs-extension/build_node/siv');
  /* eslint-enable no-undef */
}

import Crypto from './crypto';
import FireCryptError from './FireCryptError';
import FireCryptReference from './FireCryptReference';

class FireCrypt {
  constructor(db) {
    const dbIsNonNullObject = typeof db === 'object' && db !== null;
    if (!dbIsNonNullObject || typeof db.app !== 'object' || typeof db.ref !== 'function') {
      throw new Error(
        `Expected first argument passed to FireCrypt constructor to be a Firebase Database ` +
        `instance, but got "${db}".`
      );
    }

    this._db = db;
    this._crypto = undefined;
  }

  _ensureEncryptionConfigured() {
    if (typeof this._crypto === 'undefined') {
      throw new FireCryptError(
        'Encryption for this FireCrypt reference has not been configured yet.', 'BAD_CONFIG');
    }
  }

  _setupAesSiv(key, checkValue) {
    const siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
    const encryptString = strOrU8 => {
      const str = typeof strOrU8 === 'string' ? strOrU8 : CryptoJS.lib.WordArray.create(strOrU8);
      return CryptoJS.enc.Base64url.stringify(siv.encrypt(str));
    };
    const decryptString = (str, decode) => {
      const result = siv.decrypt(CryptoJS.enc.Base64url.parse(str));
      if (result === false) throw new FireCryptError('Wrong decryption key', 'WRONG_KEY');
      return decode ? CryptoJS.enc.Utf8.stringify(result) : result;
    };

    this._crypto.setStringEncryptionFunctions(encryptString, decryptString);

    if (checkValue) decryptString(checkValue, true);
    return encryptString(CryptoJS.enc.Base64url.stringify(CryptoJS.lib.WordArray.random(10)));
  }

  configureFireCrypt(options = {}, specification = {}) {
    if (typeof options !== 'object' || options === null) {
      throw new Error(
        `Expected second argument passed to configureFireCrypt() to be an object, but got ` +
        `"${options}".`
      );
    } else if (typeof specification !== 'object' || specification === null) {
      throw new Error(
        `Expected third argument passed to configureFireCrypt() to be an object, but got ` +
        `"${specification}".`
      );
    }

    options.cacheSize = options.cacheSize || 5 * 1000 * 1000;
    options.encryptionCacheSize = options.encryptionCacheSize || options.cacheSize;
    options.decryptionCacheSize = options.decryptionCacheSize || options.cacheSize;

    this._crypto = new Crypto(options, specification);

    let result;

    switch (options.encryption) {
      case 'aes-siv':
        if (!options.key) {
          throw new FireCryptError('You must specify a key to use AES encryption.', 'BAD_CONFIG');
        }
        result = this._setupAesSiv(options.key, options.keyCheckValue);
        break;
      case 'none':
        // Don't set any string encryption functions.
        break;
      case 'notready': {
        function throwNotSetUpError() {
          throw new FireCryptError('Encryption not set up', 'NO_KEY');
        }
        this._crypto.setStringEncryptionFunctions(throwNotSetUpError, throwNotSetUpError);
        break;
      }
      default:
        throw new FireCryptError(
          `Unknown encryption algorithm "${options.encryption}".`, 'BAD_CONFIG');
    }

    // Make the encryption key check value available off of this FireCrypt instance and therefore
    // off of admin.database().
    this.encryptionKeyCheckValue = result;

    return result;
  }

  get fireCryptStats() {
    this._ensureEncryptionConfigured();
    return this._crypto.stats;
  }

  goOnline() {
    this._ensureEncryptionConfigured();
    return this._db.goOnline();
  }

  goOffline() {
    this._ensureEncryptionConfigured();
    return this._db.goOffline();
  }

  get app() {
    return this._db.app;
  }

  ref(path) {
    this._ensureEncryptionConfigured();

    if (typeof path !== 'undefined' && typeof path !== 'string') {
      throw new Error(
        `Expected first argument passed to ref() to be undefined or a string, but got "${path}".`
      );
    }

    return new FireCryptReference(this._db.ref(path), this);
  }

  refFromURL(url) {
    this._ensureEncryptionConfigured();

    if (typeof url !== 'string' || url.match(/^https:\/\/.*/g) === null) {
      throw new Error(
        `Expected first argument passed to refFromURL() to be a string URL, but got "${url}".`
      );
    }

    return new FireCryptReference(this._db.refFromURL(url), this);
  }
}


export function wrapDatabase(database) {
  const fc = new FireCrypt(database);
  if (database.getRules) {
    fc.getRules = () => database.getRules();
    fc.getRulesJSON = () => database.getRulesJSON();
    fc.setRules = source => database.setRules(source);
  }
  return fc;
}
