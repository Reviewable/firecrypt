if (typeof require !== 'undefined') {
  if (typeof Firebase === 'undefined') global.Firebase = require('firebase');
  if (typeof LRUCache === 'undefined') global.LRUCache = require('lru-cache');
  if (typeof CryptoJS === 'undefined') global.CryptoJS = require('crypto-js/core');
  require('crypto-js/enc-base64');
  require('cryptojs-extension/build_node/siv');
  try {
    require('firebase-childrenkeys');
  } catch (e) {
    // ignore, not installed
  }
}

CryptoJS.enc.Base64UrlSafe = {
  stringify: CryptoJS.enc.Base64.stringify,
  parse: CryptoJS.enc.Base64.parse,
  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
};


var fbp = Firebase.prototype;
var originalQueryFbp = {};
var firebaseWrapped = false;
var encryptString, decryptString;

import * as crypto from './crypto';
import FireCryptQuery from './FireCryptQuery';
import FireCryptSnapshot from './FireCryptSnapshot';
import FireCryptOnDisconnect from './FireCryptOnDisconnect';

Firebase.initializeEncryption = function(options, specification) {
  var result;
  options.cacheSize = options.cacheSize || 5 * 1000 * 1000;
  options.encryptionCacheSize = options.encryptionCacheSize || options.cacheSize;
  options.decryptionCacheSize = options.decryptionCacheSize || options.cacheSize;
  encryptString = decryptString = crypto.throwNotSetUpError;
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
      result = setupAesSiv(options.key, options.keyCheckValue);
      break;
    case 'passthrough':
      encryptString = decryptString = function(str) {return str;};
      break;
    case 'none':
      break;
    default:
      throw new Error('Unknown encryption algorithm "' + options.algorithm + '".');
  }
  crypto.setSpec(specification);
  wrapFirebase();
  return result;
};

function setupAesSiv(key, checkValue) {
  var siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
  encryptString = function(str) {
    return CryptoJS.enc.Base64UrlSafe.stringify(siv.encrypt(str));
  };
  decryptString = function(str) {
    var result = siv.decrypt(CryptoJS.enc.Base64UrlSafe.parse(str));
    if (result === false) {
      var e = new Error('Wrong decryption key');
      e.firecrypt = 'WRONG_KEY';
      throw e;
    }
    return CryptoJS.enc.Utf8.stringify(result);
  };
  if (checkValue) decryptString(checkValue);
  return encryptString(CryptoJS.enc.Base64UrlSafe.stringify(CryptoJS.lib.WordArray.random(10)));
}

function wrapFirebase() {
  if (firebaseWrapped) return;
  interceptWrite('set', 0);
  interceptWrite('update', 0);
  interceptPush();
  interceptWrite('setWithPriority', 0);
  interceptWrite('setPriority');
  if (fbp.childrenKeys) interceptChildrenKeys();
  interceptTransaction();
  interceptOnDisconnect();
  [
    'on', 'off', 'once', 'orderByChild', 'orderByKey', 'orderByValue', 'orderByPriority',
    'startAt', 'endAt', 'equalTo', 'limitToFirst', 'limitToLast', 'limit', 'ref'
  ].forEach(function(methodName) {interceptQuery(methodName);});
  firebaseWrapped = true;
}

function interceptWrite(methodName, argIndex) {
  var originalMethod = fbp[methodName];
  fbp[methodName] = function() {
    var path = crypto.refToPath(this);
    var self = crypto.encryptRef(this, path);
    var args = Array.prototype.slice.call(arguments);
    if (argIndex >= 0 && argIndex < args.length) {
      args[argIndex] = crypto.transformValue(path, args[argIndex], crypto.encrypt);
    }
    return originalMethod.apply(self, args);
  };
}

function interceptPush() {
  // Firebase.push delegates to Firebase.set, which will take care of encrypting the ref and the
  // argument.
  var originalMethod = fbp.push;
  fbp.push = function() {
    var ref = originalMethod.apply(this, arguments);
    var decryptedRef = crypto.decryptRef(ref);
    decryptedRef.then = ref.then;
    decryptedRef.catch = ref.catch;
    if (ref.finally) decryptedRef.finally = ref.finally;
    return decryptedRef;
  };
}

function interceptChildrenKeys() {
  var originalMethod = fbp.childrenKeys;
  fbp.childrenKeys = function() {
    return originalMethod.apply(crypto.encryptRef(this), arguments).then(function(keys) {
      if (!keys.some(function(key) {return /\x91/.test(key);})) return keys;
      return keys.map(crypto.decrypt);
    });
  };
}

function interceptTransaction() {
  var originalMethod = fbp.transaction;
  fbp.transaction = function() {
    var path = crypto.refToPath(this);
    var self = crypto.encryptRef(this, path);
    var args = Array.prototype.slice.call(arguments);
    var originalCompute = args[0];
    args[0] = originalCompute && function(value) {
      value = crypto.transformValue(path, value, crypto.decrypt);
      value = originalCompute(value);
      value = crypto.transformValue(path, value, crypto.encrypt);
      return value;
    };
    if (args.length > 1) {
      var originalOnComplete = args[1];
      args[1] = originalOnComplete && function(error, committed, snapshot) {
        return originalOnComplete(error, committed, snapshot && new FireCryptSnapshot(snapshot));
      };
    }
    return originalMethod.apply(self, args).then(function(result) {
      result.snapshot = result.snapshot && new FireCryptSnapshot(result.snapshot);
      return result;
    });
  };
}

function interceptOnDisconnect() {
  var originalMethod = fbp.onDisconnect;
  fbp.onDisconnect = function() {
    var path = crypto.refToPath(this);
    return new FireCryptOnDisconnect(path, originalMethod.call(crypto.encryptRef(this, path)));
  };
}

function interceptQuery(methodName) {
  originalQueryFbp[methodName] = fbp[methodName];
  fbp[methodName] = function() {
    var query = new FireCryptQuery(crypto.encryptRef(this), {}, originalQueryFbp);
    return query[methodName].apply(query, arguments);
  };
}
