(function () {
  'use strict';

  let _spec;
  let _encryptionCache;
  let _decryptionCache;

  function setSpec(spec) {
    _spec = cleanSpecification(spec);
  }
  function setEncryptionCache(cache) {
    _encryptionCache = cache;
  }
  function setDecryptionCache(cache) {
    _decryptionCache = cache;
  }
  function cleanSpecification(def, path) {
    var keys = Object.keys(def);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (key === '.encrypt') {
        var encryptKeys = Object.keys(def[key]);
        for (var j = 0; j < encryptKeys.length; j++) {
          var encryptKey = encryptKeys[j];
          if (encryptKey !== 'key' && encryptKey !== 'value' && encryptKey !== 'few') {
            throw new Error('Illegal .encrypt subkey: ' + encryptKeys[j]);
          }
        }
      } else {
        if (/[\x00-\x1f\x7f\x91\x92\.#\[\]/]/.test(key) || /[$]/.test(key.slice(1))) {
          throw new Error('Illegal character in specification key: ' + key);
        }
        cleanSpecification(def[key], (path || '') + '/' + key);
      }
      switch (key.charAt(0)) {
        case '$':
          if (key === '$') break;
          if (def.$) throw new Error('Multiple wildcard keys in specification at ' + path);
          def.$ = def[key];
          delete def[key];
          break;
        case '.':
          if (key !== '.encrypt') throw new Error('Unknown directive at ' + path + ': ' + key);
          break;
      }
    }
    return def;
  }
  function throwNotSetUpError() {
    var e = new Error('Encryption not set up');
    e.firecrypt = 'NO_KEY';
    throw e;
  }
  function computeCacheItemSize(value, key) {
    return key.length + (typeof value === 'string' ? value.length : 4);
  }
  function encryptPath(path, def) {
    def = def || _spec.rules;
    path = path.slice();
    for (var i = 0; i < path.length; i++) {
      def = def[path[i]] || def.$;
      if (!def) break;
      if (def['.encrypt'] && def['.encrypt'].key) {
        path[i] = encrypt(path[i], 'string', def['.encrypt'].key);
      }
    }
    return path;
  }
  function encryptRef(ref, path) {
    var encryptedPath = encryptPath(path || refToPath(ref));
    return encryptedPath.length ? ref.root().child(encryptedPath.join('/')) : ref.root();
  }
  function decryptRef(ref) {
    var path = refToPath(ref, true);
    var changed = false;
    for (var i = 0; i < path.length; i++) {
      var decryptedPathSegment = decrypt(path[i]);
      if (decryptedPathSegment !== path[i]) {
        path[i] = decryptedPathSegment;
        changed = true;
      }
    }
    return changed ? ref.root().child(path.join('/')) : ref;
  }
  function specForPath(path, def) {
    def = def || _spec.rules;
    for (var i = 0; def && i < path.length; i++) {
      def = def[path[i]] || def.$;
    }
    return def;
  }
  function transformValue(path, value, transform) {
    return transformTree(value, specForPath(path), transform);
  }
  function transformTree(value, def, transform) {
    if (!def) return value;
    var type = getType(value);
    var i;
    if (/^(string|number|boolean)$/.test(type)) {
      if (def['.encrypt'] && def['.encrypt'].value) {
        value = transform(value, type, def['.encrypt'].value);
      }
    } else if (type === 'object' && value !== null) {
      var transformedValue = {};
      for (var key in value) {
        if (!value.hasOwnProperty(key)) continue;
        var subValue = value[key],
            subDef;
        if (key.indexOf('/') >= 0) {
          // for deep update keys
          var keyParts = key.split('/');
          subDef = def;
          for (i = 0; i < keyParts.length; i++) {
            if (transform === decrypt) {
              keyParts[i] = decrypt(keyParts[i]);
              subDef = subDef && (subDef[keyParts[i]] || subDef.$);
            } else {
              subDef = subDef && (subDef[keyParts[i]] || subDef.$);
              if (subDef && subDef['.encrypt'] && subDef['.encrypt'].key) {
                keyParts[i] = transform(keyParts[i], 'string', subDef['.encrypt'].key);
              }
            }
          }
          key = keyParts.join('/');
        } else {
          if (transform === decrypt) {
            key = decrypt(key);
            subDef = def[key] || def.$;
          } else {
            subDef = def[key] || def.$;
            if (subDef && subDef['.encrypt'] && subDef['.encrypt'].key) {
              key = transform(key, 'string', subDef['.encrypt'].key);
            }
          }
        }
        transformedValue[key] = transformTree(subValue, subDef, transform);
      }
      value = transformedValue;
    } else if (type === 'array') {
      if (!def.$) return value;
      for (i = 0; i < value.length; i++) value[i] = transformTree(value[i], def.$, transform);
    }
    return value;
  }
  function refToPath(ref, encrypted) {
    var root = ref.root();
    if (ref === root) return [];
    var pathStr = decodeURIComponent(ref.toString().slice(root.toString().length));
    if (!encrypted && pathStr && pathStr.charAt(0) !== '.' && /[\x00-\x1f\x7f\x91\x92\.#$\[\]]/.test(pathStr)) {
      throw new Error('Path contains invalid characters: ' + pathStr);
    }
    return pathStr.split('/');
  }
  function encrypt(value, type, pattern) {
    var cacheKey;
    if (_encryptionCache) {
      cacheKey = type.charAt(0) + pattern + '\x91' + value;
      if (_encryptionCache.has(cacheKey)) return _encryptionCache.get(cacheKey);
    }
    var result;
    if (pattern === '#') {
      result = encryptValue(value, type);
    } else {
      if (type !== 'string') {
        throw new Error('Can\'t encrypt a ' + type + ' using pattern [' + pattern + ']');
      }
      var match = value.match(compilePattern(pattern));
      if (!match) {
        throw new Error('Can\'t encrypt as value doesn\'t match pattern [' + pattern + ']: ' + value);
      }
      var i = 0;
      result = pattern.replace(/[#\.]/g, function (placeholder) {
        var part = match[++i];
        if (placeholder === '#') part = encryptValue(part, 'string');
        return part;
      });
    }
    if (_encryptionCache) _encryptionCache.set(cacheKey, result);
    return result;
  }
  function encryptValue(value, type) {
    if (!/^(string|number|boolean)$/.test(type)) throw new Error('Can\'t encrypt a ' + type);
    switch (type) {
      case 'number':
        value = '' + value;break;
      case 'boolean':
        value = value ? 't' : 'f';break;
    }
    return '\x91' + type.charAt(0).toUpperCase() + encryptString(value) + '\x92';
  }
  function decrypt(value) {
    if (_decryptionCache && _decryptionCache.has(value)) return _decryptionCache.get(value);
    if (!/\x91/.test(value)) return value;
    var result;
    var match = value.match(/^\x91(.)([^\x92]*)\x92$/);
    if (match) {
      var decryptedString = decryptString(match[2]);
      switch (match[1]) {
        case 'S':
          result = decryptedString;
          break;
        case 'N':
          result = Number(decryptedString);
          // Check for NaN, since it's the only value where x !== x.
          if (result !== result) throw new Error('Invalid encrypted number: ' + decryptedString);
          break;
        case 'B':
          if (decryptedString === 't') result = true;else if (decryptedString === 'f') result = false;else throw new Error('Invalid encrypted boolean: ' + decryptedString);
          break;
        default:
          throw new Error('Invalid encrypted value type code: ' + match[1]);
      }
    } else {
      result = value.replace(/\x91(.)([^\x92]*)\x92/g, function (match, typeCode, encryptedString) {
        if (typeCode !== 'S') throw new Error('Invalid multi-segment encrypted value: ' + typeCode);
        return decryptString(encryptedString);
      });
    }
    if (_decryptionCache) _decryptionCache.set(value, result);
    return result;
  }
  function getType(value) {
    if (Array.isArray(value)) return 'array';
    var type = typeof value;
    if (type === 'object') {
      if (value instanceof String) type = 'string';else if (value instanceof Number) type = 'number';else if (value instanceof Boolean) type = 'boolean';
    }
    return type;
  }
  var patternRegexes = {};
  function compilePattern(pattern) {
    var regex = patternRegexes[pattern];
    if (!regex) {
      regex = patternRegexes[pattern] = new RegExp('^' + pattern.replace(/\./g, '#').replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&') // escape regex chars
      .replace(/#/g, '(.*?)') + '$');
    }
    return regex;
  }

  class FireCryptSnapshot {
    constructor(snap) {
      this._ref = decryptRef(snap.ref());
      this._path = refToPath(this._ref);
      this._snap = snap;

      this._delegateSnapshot('exists');
      this._delegateSnapshot('hasChildren');
      this._delegateSnapshot('numChildren');
      this._delegateSnapshot('getPriority');
    }

    _delegateSnapshot(methodName) {
      this[methodName] = function () {
        return this._snap[methodName].apply(this._snap, arguments);
      };
    }

    val() {
      return transformValue(this._path, this._snap.val(), decrypt);
    }

    child(childPath) {
      return new FireCryptSnapshot(this._snap.child(childPath));
    }

    forEach(action) {
      return this._snap.forEach(function (childSnap) {
        return action(new FireCryptSnapshot(childSnap));
      });
    }

    hasChild(childPath) {
      childPath = encryptPath(childPath.split('/'), specForPath(this._path)).join('/');
      return this._snap.hasChild(childPath);
    }

    key() {
      return this._ref.key();
    }

    name() {
      return this._ref.name();
    }

    ref() {
      return this._ref;
    }

    exportVal() {
      return transformValue(this._path, this._snap.exportVal(), decrypt);
    }
  }

  class FireCryptOnDisconnect {
    constructor(path, originalOnDisconnect) {
      this._path = path;
      this._originalOnDisconnect = originalOnDisconnect;

      this._interceptOnDisconnectWrite('set', 0);
      this._interceptOnDisconnectWrite('update', 0);
      this._interceptOnDisconnectWrite('remove');
      this._interceptOnDisconnectWrite('setWithPriority', 0);
      this._interceptOnDisconnectWrite('cancel');
    }

    _interceptOnDisconnectWrite(methodName, argIndex) {
      this[methodName] = function () {
        const args = Array.prototype.slice.call(arguments);
        if (argIndex >= 0 && argIndex < args.length) {
          args[argIndex] = transformValue(this._path, args[argIndex], encrypt);
        }

        return this._originalOnDisconnect[methodName].apply(this._originalOnDisconnect, args);
      };
    }
  }

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
  var encryptString$1, decryptString$1;

  Firebase.initializeEncryption = function (options, specification) {
    var result;
    options.cacheSize = options.cacheSize || 5 * 1000 * 1000;
    options.encryptionCacheSize = options.encryptionCacheSize || options.cacheSize;
    options.decryptionCacheSize = options.decryptionCacheSize || options.cacheSize;
    encryptString$1 = decryptString$1 = throwNotSetUpError;
    if (typeof LRUCache === 'function') {
      setEncryptionCache(new LRUCache({
        max: options.encryptionCacheSize, length: computeCacheItemSize
      }));
      setDecryptionCache(new LRUCache({
        max: options.decryptionCacheSize, length: computeCacheItemSize
      }));
    }
    switch (options.algorithm) {
      case 'aes-siv':
        if (!options.key) throw new Error('You must specify a key to use AES encryption.');
        result = setupAesSiv(options.key, options.keyCheckValue);
        break;
      case 'passthrough':
        encryptString$1 = decryptString$1 = function (str) {
          return str;
        };
        break;
      case 'none':
        break;
      default:
        throw new Error('Unknown encryption algorithm "' + options.algorithm + '".');
    }
    setSpec(specification);
    wrapFirebase();
    return result;
  };

  function setupAesSiv(key, checkValue) {
    var siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
    encryptString$1 = function (str) {
      return CryptoJS.enc.Base64UrlSafe.stringify(siv.encrypt(str));
    };
    decryptString$1 = function (str) {
      var result = siv.decrypt(CryptoJS.enc.Base64UrlSafe.parse(str));
      if (result === false) {
        var e = new Error('Wrong decryption key');
        e.firecrypt = 'WRONG_KEY';
        throw e;
      }
      return CryptoJS.enc.Utf8.stringify(result);
    };
    if (checkValue) decryptString$1(checkValue);
    return encryptString$1(CryptoJS.enc.Base64UrlSafe.stringify(CryptoJS.lib.WordArray.random(10)));
  }

  function Query(query, order, original) {
    this._query = query;
    this._order = order || {};
    this._original = original || query;
  }
  Query.prototype.on = function (eventType, callback, cancelCallback, context) {
    wrapQueryCallback(callback);
    return this._original.on.call(this._query, eventType, callback.firecryptCallback, cancelCallback, context);
  };
  Query.prototype.off = function (eventType, callback, context) {
    if (callback && callback.firecryptCallback) callback = callback.firecryptCallback;
    return this._original.off.call(this._query, eventType, callback, context);
  };
  Query.prototype.once = function (eventType, successCallback, failureCallback, context) {
    wrapQueryCallback(successCallback);
    return this._original.once.call(this._query, eventType, successCallback && successCallback.firecryptCallback, failureCallback, context).then(function (snap) {
      return new FireCryptSnapshot(snap);
    });
  };
  Query.prototype.orderByChild = function (key) {
    return this._orderBy('orderByChild', 'child', key);
  };
  Query.prototype.orderByKey = function () {
    return this._orderBy('orderByKey', 'key');
  };
  Query.prototype.orderByValue = function () {
    return this._orderBy('orderByValue', 'value');
  };
  Query.prototype.orderByPriority = function () {
    return this._orderBy('orderByPriority', 'priority');
  };
  Query.prototype.startAt = function (value, key) {
    this._checkCanSort(key !== undefined);
    return this._delegate('startAt', arguments);
  };
  Query.prototype.endAt = function (value, key) {
    this._checkCanSort(key !== undefined);
    return this._delegate('endAt', arguments);
  };
  Query.prototype.equalTo = function (value, key) {
    if (this._order[this._order.by + 'Encrypted']) {
      value = encrypt(value, getType(value), this._order[this._order.by + 'Encrypted']);
    }
    if (key !== undefined && this._order.keyEncrypted) {
      key = encrypt(key, 'string', this._order.keyEncrypted);
    }
    return new Query(this._original.equalTo.call(this._query, value, key), this._order);
  };
  Query.prototype.limitToFirst = function () {
    return this._delegate('limitToFirst', arguments);
  };
  Query.prototype.limitToLast = function () {
    return this._delegate('limitToLast', arguments);
  };
  Query.prototype.limit = function () {
    return this._delegate('limit', arguments);
  };
  Query.prototype.ref = function () {
    return decryptRef(this._original.ref.call(this._query));
  };
  Query.prototype._delegate = function (methodName, args) {
    return new Query(this._original[methodName].apply(this._query, args), this._order);
  };
  Query.prototype._checkCanSort = function (hasExtraKey) {
    if (this._order.by === 'key' ? this._order.keyEncrypted : this._order.valueEncrypted || hasExtraKey && this._order.keyEncrypted) {
      throw new Error('Encrypted items cannot be ordered');
    }
  };
  Query.prototype._orderBy = function (methodName, by, childKey) {
    var def = specForPath(refToPath(this.ref()));
    var order = { by: by };
    var encryptedChildKey;
    if (def) {
      var childPath = childKey && childKey.split('/');
      for (var subKey in def) {
        if (!def.hasOwnProperty(subKey)) continue;
        var subDef = def[subKey];
        if (subDef['.encrypt']) {
          if (subDef['.encrypt'].key) order.keyEncrypted = subDef['.encrypt'].key;
          if (subDef['.encrypt'].value) order.valueEncrypted = subDef['.encrypt'].value;
        }
        if (childKey) {
          var childDef = specForPath(childPath, subDef);
          if (childDef && childDef['.encrypt'] && childDef['.encrypt'].value) {
            order.childEncrypted = childDef['.encrypt'].value;
          }
          var encryptedChildKeyCandidate = encryptPath(childPath, subDef).join('/');
          if (encryptedChildKey && encryptedChildKeyCandidate !== encryptedChildKey) {
            throw new Error('Incompatible encryption specifications for orderByChild("' + childKey + '")');
          }
          encryptedChildKey = encryptedChildKeyCandidate;
        }
      }
    }
    if (childKey) {
      return new Query(this._original[methodName].call(this._query, encryptedChildKey || childKey), order);
    } else {
      return new Query(this._original[methodName].call(this._query), order);
    }
  };

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
    ['on', 'off', 'once', 'orderByChild', 'orderByKey', 'orderByValue', 'orderByPriority', 'startAt', 'endAt', 'equalTo', 'limitToFirst', 'limitToLast', 'limit', 'ref'].forEach(function (methodName) {
      interceptQuery(methodName);
    });
    firebaseWrapped = true;
  }

  function interceptWrite(methodName, argIndex) {
    var originalMethod = fbp[methodName];
    fbp[methodName] = function () {
      var path = refToPath(this);
      var self = encryptRef(this, path);
      var args = Array.prototype.slice.call(arguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = transformValue(path, args[argIndex], encrypt);
      }
      return originalMethod.apply(self, args);
    };
  }

  function interceptPush() {
    // Firebase.push delegates to Firebase.set, which will take care of encrypting the ref and the
    // argument.
    var originalMethod = fbp.push;
    fbp.push = function () {
      var ref = originalMethod.apply(this, arguments);
      var decryptedRef = decryptRef(ref);
      decryptedRef.then = ref.then;
      decryptedRef.catch = ref.catch;
      if (ref.finally) decryptedRef.finally = ref.finally;
      return decryptedRef;
    };
  }

  function interceptChildrenKeys() {
    var originalMethod = fbp.childrenKeys;
    fbp.childrenKeys = function () {
      return originalMethod.apply(encryptRef(this), arguments).then(function (keys) {
        if (!keys.some(function (key) {
          return (/\x91/.test(key)
          );
        })) return keys;
        return keys.map(decrypt);
      });
    };
  }

  function interceptTransaction() {
    var originalMethod = fbp.transaction;
    fbp.transaction = function () {
      var path = refToPath(this);
      var self = encryptRef(this, path);
      var args = Array.prototype.slice.call(arguments);
      var originalCompute = args[0];
      args[0] = originalCompute && function (value) {
        value = transformValue(path, value, decrypt);
        value = originalCompute(value);
        value = transformValue(path, value, encrypt);
        return value;
      };
      if (args.length > 1) {
        var originalOnComplete = args[1];
        args[1] = originalOnComplete && function (error, committed, snapshot) {
          return originalOnComplete(error, committed, snapshot && new FireCryptSnapshot(snapshot));
        };
      }
      return originalMethod.apply(self, args).then(function (result) {
        result.snapshot = result.snapshot && new FireCryptSnapshot(result.snapshot);
        return result;
      });
    };
  }

  function interceptOnDisconnect() {
    var originalMethod = fbp.onDisconnect;
    fbp.onDisconnect = function () {
      var path = refToPath(this);
      return new FireCryptOnDisconnect(path, originalMethod.call(encryptRef(this, path)));
    };
  }

  function interceptQuery(methodName) {
    originalQueryFbp[methodName] = fbp[methodName];
    fbp[methodName] = function () {
      var query = new Query(encryptRef(this), {}, originalQueryFbp);
      return query[methodName].apply(query, arguments);
    };
  }

  function wrapQueryCallback(callback) {
    if (!callback || callback.firecryptCallback) return;
    var wrappedCallback = function (snap, previousChildKey) {
      return callback.call(this, new FireCryptSnapshot(snap), previousChildKey);
    };
    wrappedCallback.firecryptCallback = wrappedCallback;
    callback.firecryptCallback = wrappedCallback;
  }

}());
//# sourceMappingURL=firecrypt.js.map
