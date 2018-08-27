var FireCrypt = (function () {
  'use strict';

  class Crypto {
    constructor(options, spec) {
      this._spec = this._cleanSpecification(spec);
      this._encryptString = this._throwNotSetUpError;
      this._decryptString = this._throwNotSetUpError;

      this._patternRegexes = {};

      if (typeof LRUCache === 'function') {
        this._encryptionCache = new LRUCache({
          max: options.encryptionCacheSize,
          length: this._computeCacheItemSize
        });
        this._decryptionCache = new LRUCache({
          max: options.decryptionCacheSize,
          length: this._computeCacheItemSize
        });
      }
    }

    _cleanSpecification(def, path) {
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
          this._cleanSpecification(def[key], (path || '') + '/' + key);
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

    _throwNotSetUpError() {
      var e = new Error('Encryption not set up');
      e.firecrypt = 'NO_KEY';
      throw e;
    }

    _computeCacheItemSize(value, key) {
      return key.length + (typeof value === 'string' ? value.length : 4);
    }

    setStringEncryptionFunctions(encryptString, decryptString) {
      this._encryptString = encryptString;
      this._decryptString = decryptString;
    }

    encryptPath(path, def) {
      def = def || this._spec.rules;
      path = path.slice();
      for (var i = 0; i < path.length; i++) {
        def = def[path[i]] || def.$;
        if (!def) break;
        if (def['.encrypt'] && def['.encrypt'].key) {
          path[i] = this.encrypt(path[i], 'string', def['.encrypt'].key);
        }
      }
      return path;
    }

    encryptRef(ref, path) {
      var encryptedPath = this.encryptPath(path || this.refToPath(ref));
      return encryptedPath.length ? ref.root.child(encryptedPath.join('/')) : ref.root;
    }

    decryptRef(ref) {
      var path = this.refToPath(ref, true);
      var changed = false;
      for (var i = 0; i < path.length; i++) {
        var decryptedPathSegment = this.decrypt(path[i]);
        if (decryptedPathSegment !== path[i]) {
          path[i] = decryptedPathSegment;
          changed = true;
        }
      }
      return changed ? ref.root.child(path.join('/')) : ref;
    }

    specForPath(path, def) {
      def = def || this._spec.rules;
      for (var i = 0; def && i < path.length; i++) {
        def = def[path[i]] || def.$;
      }
      return def;
    }

    transformValue(path, value, transformType) {
      if (transformType !== 'encrypt' && transformType !== 'decrypt') {
        throw new Error(`Transform type must be either "encrypt" or "decrypt", but got "${transformType}".`);
      }
      const transform = transformType === 'encrypt' ? this.encrypt.bind(this) : this.decrypt.bind(this);
      return this.transformTree(value, this.specForPath(path), transform);
    }

    transformTree(value, def, transform) {
      if (!def) return value;
      var type = this.getType(value);
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
                keyParts[i] = this.decrypt(keyParts[i]);
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
            if (transform === this.decrypt) {
              key = this.decrypt(key);
              subDef = def[key] || def.$;
            } else {
              subDef = def[key] || def.$;
              if (subDef && subDef['.encrypt'] && subDef['.encrypt'].key) {
                key = transform(key, 'string', subDef['.encrypt'].key);
              }
            }
          }
          transformedValue[key] = this.transformTree(subValue, subDef, transform);
        }
        value = transformedValue;
      } else if (type === 'array') {
        if (!def.$) return value;
        for (i = 0; i < value.length; i++) value[i] = this.transformTree(value[i], def.$, transform);
      }
      return value;
    }

    refToPath(ref, encrypted) {
      var root = ref.root;
      if (ref === root) return [];
      var pathStr = decodeURIComponent(ref.toString().slice(root.toString().length));
      if (!encrypted && pathStr && pathStr.charAt(0) !== '.' && /[\x00-\x1f\x7f\x91\x92\.#$\[\]]/.test(pathStr)) {
        throw new Error('Path contains invalid characters: ' + pathStr);
      }
      return pathStr.split('/');
    }

    encrypt(value, type, pattern) {
      var cacheKey;
      if (this._encryptionCache) {
        cacheKey = type.charAt(0) + pattern + '\x91' + value;
        if (this._encryptionCache.has(cacheKey)) return this._encryptionCache.get(cacheKey);
      }
      var result;
      if (pattern === '#') {
        result = this.encryptValue(value, type);
      } else {
        if (type !== 'string') {
          throw new Error('Can\'t encrypt a ' + type + ' using pattern [' + pattern + ']');
        }
        var match = value.match(this.compilePattern(pattern));
        if (!match) {
          throw new Error('Can\'t encrypt as value doesn\'t match pattern [' + pattern + ']: ' + value);
        }
        var i = 0;
        result = pattern.replace(/[#\.]/g, function (placeholder) {
          var part = match[++i];
          if (placeholder === '#') part = this.encryptValue(part, 'string');
          return part;
        });
      }
      if (this._encryptionCache) this._encryptionCache.set(cacheKey, result);
      return result;
    }

    encryptValue(value, type) {
      if (!/^(string|number|boolean)$/.test(type)) throw new Error('Can\'t encrypt a ' + type);
      switch (type) {
        case 'number':
          value = '' + value;break;
        case 'boolean':
          value = value ? 't' : 'f';break;
      }
      return '\x91' + type.charAt(0).toUpperCase() + this._encryptString(value) + '\x92';
    }

    decrypt(value) {
      if (this._decryptionCache && this._decryptionCache.has(value)) return this._decryptionCache.get(value);
      if (!/\x91/.test(value)) return value;
      var result;
      var match = value.match(/^\x91(.)([^\x92]*)\x92$/);
      if (match) {
        var decryptedString = this._decryptString(match[2]);
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
          return this._decryptString(encryptedString);
        });
      }
      if (this._decryptionCache) this._decryptionCache.set(value, result);
      return result;
    }

    getType(value) {
      if (Array.isArray(value)) return 'array';
      var type = typeof value;
      if (type === 'object') {
        if (value instanceof String) type = 'string';else if (value instanceof Number) type = 'number';else if (value instanceof Boolean) type = 'boolean';
      }
      return type;
    }

    compilePattern(pattern) {
      var regex = this._patternRegexes[pattern];
      if (!regex) {
        regex = this._patternRegexes[pattern] = new RegExp('^' + pattern.replace(/\./g, '#').replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&') // escape regex chars
        .replace(/#/g, '(.*?)') + '$');
      }
      return regex;
    }
  }

  class FireCryptSnapshot {
    constructor(snap, crypto) {
      this._ref = crypto.decryptRef(snap.ref);
      this._path = crypto.refToPath(this._ref);
      this._snap = snap;
      this._crypto = crypto;
    }

    get key() {
      return this._ref.key;
    }

    get ref() {
      return new FireCryptReference(this._ref.ref, this._crypto);
    }

    val() {
      return this._crypto.transformValue(this._path, this._snap.val(), 'decrypt');
    }

    child(childPath) {
      return new FireCryptSnapshot(this._snap.child(childPath), this._crypto);
    }

    forEach(action) {
      return this._snap.forEach(childSnap => {
        return action(new FireCryptSnapshot(childSnap), this._crypto);
      });
    }

    exists() {
      return this._snap.exists.apply(this._snap, arguments);
    }

    hasChild(childPath) {
      childPath = this._crypto.encryptPath(childPath.split('/'), this._crypto.specForPath(this._path)).join('/');
      return this._snap.hasChild(childPath);
    }

    hasChildren() {
      return this._snap.hasChildren.apply(this._snap, arguments);
    }

    numChildren() {
      return this._snap.numChildren.apply(this._snap, arguments);
    }

    toJSON() {
      const json = this._snap.toJSON.apply(this._snap, arguments);
      return this._crypto.transformValue(this._path, json, 'decrypt');
    }
  }

  class FireCryptQuery {
    constructor(query, order, originalRef, crypto) {
      this._query = query;
      this._order = order || {};
      this._originalRef = originalRef || query;
      this._crypto = crypto;
    }

    _wrapQueryCallback(callback) {
      if (!callback || callback.firecryptCallback) return;
      const wrappedCallback = (snap, previousChildKey) => {
        return callback.call(this, new FireCryptSnapshot(snap, this._crypto), previousChildKey, this._crypto);
      };
      wrappedCallback.firecryptCallback = wrappedCallback;
      callback.firecryptCallback = wrappedCallback;
    }

    get ref() {
      return new FireCryptReference(this._crypto.decryptRef(this._query.ref), this._crypto);
    }

    on(eventType, callback, cancelCallback, context) {
      this._wrapQueryCallback(callback);
      return this._originalRef.on.call(this._query, eventType, callback.firecryptCallback, cancelCallback, context);
    }

    off(eventType, callback, context) {
      if (callback && callback.firecryptCallback) callback = callback.firecryptCallback;
      return this._originalRef.off.call(this._query, eventType, callback, context);
    }

    once(eventType, successCallback, failureCallback, context) {
      this._wrapQueryCallback(successCallback);
      return this._originalRef.once.call(this._query, eventType, successCallback && successCallback.firecryptCallback, failureCallback, context).then(snap => {
        return new FireCryptSnapshot(snap, this._crypto);
      });
    }

    orderByChild(key) {
      return this._orderBy('orderByChild', 'child', key);
    }

    orderByKey() {
      return this._orderBy('orderByKey', 'key');
    }

    orderByValue() {
      return this._orderBy('orderByValue', 'value');
    }

    startAt(value, key) {
      this._checkCanSort(key !== undefined);
      return this._delegate('startAt', arguments);
    }

    endAt(value, key) {
      this._checkCanSort(key !== undefined);
      return this._delegate('endAt', arguments);
    }

    equalTo(value, key) {
      if (this._order[this._order.by + 'Encrypted']) {
        value = this._crypto.encrypt(value, this._crypto.getType(value), this._order[this._order.by + 'Encrypted']);
      }
      if (key !== undefined && this._order.keyEncrypted) {
        key = this._crypto.encrypt(key, 'string', this._order.keyEncrypted);
      }
      return new FireCryptQuery(this._originalRef.equalTo.call(this._query, value, key), this._order, this._crypto);
    }

    limitToFirst() {
      return this._delegate('limitToFirst', arguments);
    }

    limitToLast() {
      return this._delegate('limitToLast', arguments);
    }

    limit() {
      return this._delegate('limit', arguments);
    }

    _delegate(methodName, args) {
      return new FireCryptQuery(this._originalRef[methodName].apply(this._query, args), this._order, this._crypto);
    }

    _checkCanSort(hasExtraKey) {
      if (this._order.by === 'key' ? this._order.keyEncrypted : this._order.valueEncrypted || hasExtraKey && this._order.keyEncrypted) {
        throw new Error('Encrypted items cannot be ordered');
      }
    }

    _orderBy(methodName, by, childKey) {
      const def = this._crypto.specForPath(this._crypto.refToPath(this.ref));
      const order = { by: by };

      let encryptedChildKey;
      if (def) {
        const childPath = childKey && childKey.split('/');
        for (const subKey in def) {
          if (!def.hasOwnProperty(subKey)) continue;
          const subDef = def[subKey];
          if (subDef['.encrypt']) {
            if (subDef['.encrypt'].key) order.keyEncrypted = subDef['.encrypt'].key;
            if (subDef['.encrypt'].value) order.valueEncrypted = subDef['.encrypt'].value;
          }
          if (childKey) {
            const childDef = this._crypto.specForPath(childPath, subDef);
            if (childDef && childDef['.encrypt'] && childDef['.encrypt'].value) {
              order.childEncrypted = childDef['.encrypt'].value;
            }
            const encryptedChildKeyCandidate = this._crypto.encryptPath(childPath, subDef).join('/');
            if (encryptedChildKey && encryptedChildKeyCandidate !== encryptedChildKey) {
              throw new Error('Incompatible encryption specifications for orderByChild("' + childKey + '")');
            }
            encryptedChildKey = encryptedChildKeyCandidate;
          }
        }
      }
      if (childKey) {
        return new FireCryptQuery(this._originalRef[methodName].call(this._query, encryptedChildKey || childKey), order, this._crypto);
      } else {
        return new FireCryptQuery(this._originalRef[methodName].call(this._query), order, this._crypto);
      }
    }
  }

  class FireCryptOnDisconnect {
    constructor(path, originalOnDisconnect, crypto) {
      this._path = path;
      this._crypto = crypto;
      this._originalOnDisconnect = originalOnDisconnect;
    }

    _interceptOnDisconnectWrite(methodName, originalArguments, argIndex) {
      const self = this;

      this[methodName] = function () {
        const args = Array.prototype.slice.call(originalArguments);
        if (argIndex >= 0 && argIndex < args.length) {
          args[argIndex] = self._crypto.transformValue(self._path, args[argIndex], 'encrypt');
        }

        return self._originalOnDisconnect[methodName].apply(self._originalOnDisconnect, args);
      };
    }

    set() {
      return this._interceptOnDisconnectWrite('set', arguments, 0);
    }

    update() {
      return this._interceptOnDisconnectWrite('update', arguments, 0);
    }

    remove() {
      return this._interceptOnDisconnectWrite('remove', arguments);
    }

    cancel() {
      return this._interceptOnDisconnectWrite('cancel', arguments);
    }
  }

  let childrenKeysFromLib;
  try {
    childrenKeysFromLib = require('firebase-childrenkeys');
  } catch (e) {
    // Library is optional, so ignore any errors from failure to load it.
  }

  class FireCryptReference {
    constructor(ref, crypto) {
      this._ref = ref;
      this._crypto = crypto;
    }

    _interceptQuery(methodName, originalArguments) {
      const encryptedRef = this._crypto.encryptRef(this._ref);
      const query = new FireCryptQuery(encryptedRef, {}, this._ref, this._crypto);
      return query[methodName].apply(query, originalArguments);
    }

    _interceptWrite(methodName, originalArguments, argIndex) {
      const encryptedRef = this._crypto.encryptRef(this._ref);

      const args = Array.prototype.slice.call(originalArguments);
      if (argIndex >= 0 && argIndex < args.length) {
        const path = this._crypto.refToPath(this._ref);
        args[argIndex] = this._crypto.transformValue(path, args[argIndex], 'encrypt');
      }

      return this._ref[methodName].apply(encryptedRef, args);
    }

    /**
     * Returns a placeholder value for auto-populating the current timestamp (time since the Unix
     * epoch, in milliseconds) as determined by the Firebase servers.
     * @return {Object} A timestamp placeholder value.
     */
    static get SERVER_TIMESTAMP() {
      return {
        '.sv': 'timestamp'
      };
    }

    /**
     * Returns the last part of this reference's path. The key of a root reference is `null`.
     * @return {string|null} The last part this reference's path.
     */
    get key() {
      return this._ref.key;
    }

    /**
     * Returns just the path component of the reference's URL.
     * @return {string} The path component of the Firebase URL wrapped by this reference.
     */
    get path() {
      return decodeURIComponent(this._ref.toString()).slice(this._ref.root.toString().length - 1);
    }

    /**
     * Returns a FireCryptReference at the same location as this query or reference.
     * @return {FireCryptReference|null} A FireCryptReference at the same location as this query or
     *     reference.
     */
    get ref() {
      if (this._ref.isEqual(this._ref.ref)) {
        return this;
      } else {
        return new FireCryptReference(this._ref.ref, this._crypto);
      }
    }

    /**
     * Returns a FireCryptReference reference to the root of the database.
     * @return {FireCryptReference} The root reference of the database.
     */
    get root() {
      if (this._ref.isEqual(this._ref.root)) {
        return this;
      } else {
        return new FireCryptReference(this._ref.root, this._crypto);
      }
    }

    /**
     * Returns a FireCryptReference to the parent location of this reference. The parent of a root
     * reference is `null`.
     * @return {FireCryptReference|null} The parent location of this reference.
     */
    get parent() {
      if (this._ref.parent === null) {
        return null;
      } else {
        return new FireCryptReference(this._ref.parent, this._crypto);
      }
    }

    /**
     * Creates a new FireCryptReference object on a child of this one.
     * @param  {string} path The path to the desired child, relative to this reference.
     * @return {FireCryptReference} The child reference.
     */
    child(path) {
      return new FireCryptReference(this._ref.child(path), this._crypto);
    }

    /**
     * Returns a JSON-serializable representation of this object.
     * @return {Object} A JSON-serializable representation of this object.
     */
    toJSON() {
      return this._ref.toJSON();
    }

    /**
     * Returns whether or not this FireCryptReference is equivalent to the provided FireCryptReference.
     * @return {FireCryptReference} Another FireCryptReference instance against which to compare.
     */
    isEqual(otherRef) {
      return this._ref.isEqual(otherRef._ref);
    }

    /**
     * Stringifies the wrapped reference.
     * @return {string} The Firebase URL wrapped by this FireCryptReference object.
     */
    toString() {
      return decodeURIComponent(this._ref.toString());
    }

    push() {
      const pushedRef = this.child(this._ref.push().key);

      let promise;
      if (typeof arguments[0] === 'undefined') {
        // A bare pushed ref should also be thennable.
        promise = Promise.resolve();
      } else {
        promise = pushedRef.set.apply(pushedRef, arguments);
      }

      pushedRef.then = promise.then.bind(promise);
      pushedRef.catch = promise.catch.bind(promise);
      if (promise.finally) pushedRef.finally = promise.finally.bind(promise);

      return pushedRef;
    }

    set() {
      return this._interceptWrite('set', arguments, 0);
    }

    remove() {
      return this._interceptWrite('remove', arguments);
    }

    update() {
      return this._interceptWrite('update', arguments, 0);
    }

    childrenKeys() {
      const originalMethod = this._ref.childrenKeys || childrenKeysFromLib;

      if (typeof originalMethod !== 'function') {
        throw new Error(`childrenKeys() is not implemented. You must either provide a Firebase Database Reference
        which implements childrenKeys() or npm install the firebase-children keys libary.`);
      }

      const encryptedRef = this._crypto.encryptRef(this._ref);
      return originalMethod.apply(encryptedRef, [encryptedRef, ...arguments]).then(keys => {
        if (!keys.some(key => /\x91/.test(key))) {
          return keys;
        }
        return keys.map(this._crypto.decrypt.bind(this._crypto));
      });
    }

    onDisconnect() {
      const encryptedRef = this._crypto.encryptRef(this._ref);
      return new FireCryptOnDisconnect(encryptedRef, this._ref.onDisconnect.call(encryptedRef), this._crypto);
    }

    on() {
      return this._interceptQuery('on', arguments);
    }

    off() {
      return this._interceptQuery('off', arguments);
    }

    once() {
      return this._interceptQuery('once', arguments);
    }

    orderByChild() {
      return this._interceptQuery('orderByChild', arguments);
    }

    orderByKey() {
      return this._interceptQuery('orderByKey', arguments);
    }

    orderByValue() {
      return this._interceptQuery('orderByValue', arguments);
    }

    startAt() {
      return this._interceptQuery('startAt', arguments);
    }

    endAt() {
      return this._interceptQuery('endAt', arguments);
    }

    equalTo() {
      return this._interceptQuery('equalTo', arguments);
    }

    limitToFirst() {
      return this._interceptQuery('limitToFirst', arguments);
    }

    limitToLast() {
      return this._interceptQuery('limitToLast', arguments);
    }

    transaction() {
      const encryptedRef = this._crypto.encryptRef(this._ref);
      const path = this._crypto.refToPath(this._ref);

      const args = Array.prototype.slice.call(arguments);
      const originalCompute = args[0];
      args[0] = originalCompute && (value => {
        value = this._crypto.transformValue(path, value, 'decrypt');
        value = originalCompute(value);
        value = this._crypto.transformValue(path, value, 'encrypt');
        return value;
      });
      if (args.length > 1) {
        const originalOnComplete = args[1];
        args[1] = originalOnComplete && ((error, committed, snapshot) => {
          return originalOnComplete(error, committed, snapshot && new FireCryptSnapshot(snapshot));
        });
      }
      return this._ref.transaction.apply(encryptedRef, args).then(result => {
        result.snapshot = result.snapshot && new FireCryptSnapshot(result.snapshot, this._crypto);
        return result;
      });
    }
  }

  const patchFirebaseDatabaseApi = fb => {
    const originalDb = fb.database;
    Object.defineProperty(fb, 'database', {
      value: () => new FireCrypt(originalDb.call(fb))
    });

    const patchedApps = [];

    const originalApp = fb.app;
    Object.defineProperty(fb, 'app', {
      value: () => {
        const app = originalApp.call(fb);
        if (patchedApps.indexOf(app.name) === -1) {
          patchedApps.push(app.name);
          const fc = new FireCrypt(originalDb.call(fb));
          app.database = () => fc;
        }
        return app;
      }
    });
  };

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
    throw new Error('The Firebase web SDK must be loaded before FireCrypt.');
  }

  CryptoJS.enc.Base64UrlSafe = {
    stringify: CryptoJS.enc.Base64.stringify,
    parse: CryptoJS.enc.Base64.parse,
    _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  };

  class FireCrypt {
    constructor(db) {
      const dbIsNonNullObject = typeof db === 'object' && db !== null;
      if (!dbIsNonNullObject || typeof db.app !== 'object' || typeof db.ref !== 'function') {
        throw new Error(`Expected first argument passed to FireCrypt constructor to be a Firebase Database instance, 
        but got "${db}".`);
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
      const encryptString = str => {
        return CryptoJS.enc.Base64UrlSafe.stringify(siv.encrypt(str));
      };
      const decryptString = str => {
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
        throw new Error(`Expected second argument passed to configureEncryption() to be an object, but got "${options}".`);
      } else if (typeof specification !== 'object' || specification === null) {
        throw new Error(`Expected third argument passed to configureEncryption() to be an object, but got "${specification}".`);
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
          this._crypto.setStringEncryptionFunctions(str => str, str => str);
          break;
        case 'none':
          break;
        default:
          throw new Error('Unknown encryption algorithm "' + options.algorithm + '".');
      }

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
        throw new Error(`Expected first argument passed to ref() to be undefined or a string, but got "${path}".`);
      }

      return new FireCryptReference(this._db.ref(path), this._crypto);
    }

    refFromURL(url) {
      this._ensureEncryptionConfigured();

      if (typeof url !== 'string' || url.match(/^https:\/\/.*/g) === null) {
        throw new Error(`Expected first argument passed to refFromURL() to be a string URL, but got "${url}".`);
      }

      return new FireCryptReference(this._db.refFromURL(path), this._crypto);
    }
  }

  return FireCrypt;

}());
//# sourceMappingURL=firecrypt.js.map
