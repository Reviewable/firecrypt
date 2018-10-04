const patchFirebaseDatabaseApi = (fb) => {
  // We want to wrap all instances of the Firebase database() with FireCrypt.  These are always
  // eventually instantiated via an App's database() function, so we'd like to override that.
  // However, we can't get at the App prototype directly so instead we patch initializeApp(),
  // which must be called for an app instance to become available, and patch the App prototype
  // on the first call.  Once the prototype is patched, we can restore the original initializeApp.
  const originalInitializeApp = fb.initializeApp;
  Object.defineProperty(fb, 'initializeApp', {value: function() {
    const app = originalInitializeApp.apply(this, arguments);
    const originalDatabase = app.constructor.prototype.database;
    Object.defineProperty(app.constructor.prototype, 'database', {value: function() {
      // The database() call caches databases by URL and can return the same instance on separate
      // calls.  Ensure that there's a 1-to-1 correspondance between database instances and
      // FireCrypt wrappers by associating a wrapper with its underlying database.
      const db = originalDatabase.apply(this, arguments);
      if (!db.firecrypt) {
        Object.defineProperty(db, 'firecrypt', {value: new FireCrypt(db)});
      }
      return db.firecrypt;
    }});
    Object.defineProperty(fb, 'initializeApp', {value: originalInitializeApp});
    return app;
  }, configurable: true})
}

if (typeof require !== 'undefined') {
  if (typeof LRUCache === 'undefined') global.LRUCache = require('lru-cache');
  if (typeof CryptoJS === 'undefined') global.CryptoJS = require('crypto-js/core');
  require('crypto-js/enc-base64');
  require('cryptojs-extension/build_node/siv');
  const admin = require('firebase-admin');
  patchFirebaseDatabaseApi(admin);
} else if (typeof firebase !== 'undefined') {
  patchFirebaseDatabaseApi(firebase);
} else {
  throw new Error('The Firebase web client SDK must be loaded before FireCrypt.')
}

CryptoJS.enc.Base64UrlSafe = {
  stringify: CryptoJS.enc.Base64.stringify,
  parse: CryptoJS.enc.Base64.parse,
  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
};

import Crypto from './crypto';
import FireCryptReference from './FireCryptReference';

class FireCrypt {
  constructor(db) {
    const dbIsNonNullObject = typeof db === 'object' && db !== null;
    if (!dbIsNonNullObject || typeof db.app !== 'object' || typeof db.ref !== 'function') {
      throw new Error(
        `Expected first argument passed to FireCrypt constructor to be a Firebase Database instance, 
        but got "${db}".`
      );
    }

    this._db = db;
    this._crypto = undefined;
  }

  _ensureEncryptionConfigured() {
    if (typeof this._crypto === 'undefined') {
      throw new Error('Encryption for this FireCrypt reference has not been configured yet.');
    }
  }

  _setupAesSiv(key, checkValue) {
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
  
    this._crypto.setStringEncryptionFunctions(encryptString, decryptString);
  
    if (checkValue) decryptString(checkValue);
    return encryptString(CryptoJS.enc.Base64UrlSafe.stringify(CryptoJS.lib.WordArray.random(10)));
  }

  get app() {
    return this._db.app;
  }

  configureEncryption(options = {}, specification = {}) {
    if (typeof options !== 'object' || options === null) {
      throw new Error(
        `Expected second argument passed to configureEncryption() to be an object, but got "${options}".`
      );
    } else if (typeof specification !== 'object' || specification === null) {
      throw new Error(
        `Expected third argument passed to configureEncryption() to be an object, but got "${specification}".`
      );
    }

    options.cacheSize = options.cacheSize || 5 * 1000 * 1000;
    options.encryptionCacheSize = options.encryptionCacheSize || options.cacheSize;
    options.decryptionCacheSize = options.decryptionCacheSize || options.cacheSize;

    this._crypto = new Crypto(options, specification);

    let result;

    switch (options.algorithm) {
      case 'aes-siv':
        if (!options.key) throw new Error('You must specify a key to use AES encryption.');
        result = this._setupAesSiv(options.key, options.keyCheckValue);
        break;
      case 'passthrough':
        this._crypto.setStringEncryptionFunctions((str) => str, (str) => str);
        break;
      case 'none':
        break;
      default:
        throw new Error('Unknown encryption algorithm "' + options.algorithm + '".');
    }

    // Make the encryption key check value available off of this FireCrypt instance and therefore
    // off of admin.database().
    this.encryptionKeyCheckValue = result;

    return result;
  }

  goOnline() {
    this._ensureEncryptionConfigured();
    return this._db.goOnline();
  }

  goOffline() {
    this._ensureEncryptionConfigured();
    return this._db.goOffline();
  }

  ref(path) {
    this._ensureEncryptionConfigured();

    if (typeof path !== 'undefined' && typeof path !== 'string') {
      throw new Error(
        `Expected first argument passed to ref() to be undefined or a string, but got "${path}".`
      );
    }

    return new FireCryptReference(this._db.ref(path), this._crypto);
  }

  refFromURL(url) {
    this._ensureEncryptionConfigured();

    if (typeof url !== 'string' || url.match(/^https:\/\/.*/g) === null) {
      throw new Error(
        `Expected first argument passed to refFromURL() to be a string URL, but got "${url}".`
      );
    }

    return new FireCryptReference(this._db.refFromURL(path), this._crypto);
  }
}
