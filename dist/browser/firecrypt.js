var firecrypt = (function (exports) {
  'use strict';

  class FireCryptError extends Error {
    constructor(message, code) {
      super(message);
      this.firecrypt = code;
    }
  }

  class Crypto {
    constructor(options, spec) {
      this._spec = this._cleanSpecification(spec);
      this._patternRegexes = {};
      this.stats = {
        compression: {attempts: 0, thresholdAccuracy: 0, bytesIn: 0, bytesOut: 0, ratio: 0}
      };

      switch (options.compression) {
        case 'deflate':
          this._compress = str => {
            const inputU8 = fflate.strToU8(str);
            const outputU8 = fflate.deflateSync(inputU8, {level: 9});
            const reduced = inputU8.byteLength > outputU8.byteLength;
            const stats = this.stats.compression;
            stats.thresholdAccuracy =
              (stats.thresholdAccuracy * stats.attempts + reduced) / ++stats.attempts;
            if (reduced) {
              stats.bytesIn += inputU8.byteLength;
              stats.bytesOut += outputU8.byteLength;
              stats.ratio = stats.bytesOut / stats.bytesIn;
            }
            return reduced ? outputU8 : str;
          };
          break;
        case 'none':
          break;
        default:
          throw new FireCryptError(
            `Unknown compression algorithm "${options.compression}".`, 'BAD_CONFIG');
      }
      this._compressionThreshold = options.compressionThreshold || 150;

      if (typeof LRUCache === 'function') {
        this._encryptionCache = new LRUCache({
          max: options.encryptionCacheSize,
          length: this._computeCacheItemSize,
        });
        this._decryptionCache = new LRUCache({
          max: options.decryptionCacheSize,
          length: this._computeCacheItemSize,
        });
      }

      if (typeof Buffer !== 'undefined') {
        /* eslint-disable no-undef */
        this._base64UrlFromU8 = u8 => Buffer.from(u8).toString('base64url');
        this._base64UrlToU8 = str => Buffer.from(str, 'base64url');
        /* eslint-enable no-undef */
      }
    }

    _cleanSpecification(def, path) {
      const keys = Object.keys(def);
      for (const key of keys) {
        if (key === '.encrypt') {
          const encryptKeys = Object.keys(def[key]);
          for (const encryptKey of encryptKeys) {
            if (encryptKey !== 'key' && encryptKey !== 'value' && encryptKey !== 'few') {
              throw new FireCryptError(`Illegal .encrypt subkey: ${encryptKey}`, 'BAD_SPEC');
            }
          }
        } else {
          // eslint-disable-next-line no-control-regex
          if (/[\x00-\x1f\x7f\x91\x92.#[\]/]/.test(key) || /[$]/.test(key.slice(1))) {
            throw new FireCryptError(`Illegal character in specification key: ${key}`, 'BAD_SPEC');
          }
          this._cleanSpecification(def[key], (path || '') + '/' + key);
        }
        switch (key.charAt(0)) {
          case '$':
            if (key === '$') break;
            if (def.$) {
              throw new FireCryptError(
                `Multiple wildcard keys in specification at ${path}`, 'BAD_SPEC');
            }
            def.$ = def[key];
            delete def[key];
            break;
          case '.':
            if (key !== '.encrypt') {
              throw new FireCryptError(`Unknown directive at ${path}: ${key}`, 'BAD_SPEC');
            }
            break;
        }
      }
      return def;
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
      for (let i = 0; i < path.length; i++) {
        def = def[path[i]] || def.$;
        if (!def) break;
        if (def['.encrypt'] && def['.encrypt'].key) {
          path[i] = this.encrypt(path[i], 'string', def['.encrypt'].key, false);
        }
      }
      return path;
    }

    encryptRef(ref, path) {
      const encryptedPath = this.encryptPath(path || this.refToPath(ref));
      return encryptedPath.length ? ref.root.child(encryptedPath.join('/')) : ref.root;
    }

    decryptRef(ref) {
      const path = this.refToPath(ref, true);
      try {
        let changed = false;
        for (let i = 0; i < path.length; i++) {
          const decryptedPathSegment = this.decrypt(path[i]);
          if (decryptedPathSegment !== path[i]) {
            path[i] = decryptedPathSegment;
            changed = true;
          }
        }
        return changed ? ref.root.child(path.join('/')) : ref;
      } catch (e) {
        if (e.firecrypt) e.firecryptPath = path.join('/');
        throw e;
      }
    }

    specForPath(path, def) {
      def = def || this._spec.rules;
      for (let i = 0; def && i < path.length; i++) {
        def = def[path[i]] || def.$;
      }
      return def;
    }

    transformValue(path, value, transformType) {
      if (transformType !== 'encrypt' && transformType !== 'decrypt') {
        throw new Error(
          `Internal error: transform type must be either "encrypt" or "decrypt", ` +
          `but got "${transformType}".`
        );
      }
      try {
        return this._transformTree(value, this.specForPath(path), transformType);
      } catch (e) {
        if (e.firecrypt) e.firecryptPath = path;
        throw e;
      }
    }

    _transformTree(value, def, transformType) {
      // transformType is either 'encrypt' or 'decrypt'.
      if (!def) return value;
      const type = this.getType(value);
      let i;
      if (/^(string|number|boolean)$/.test(type)) {
        if (def['.encrypt'] && def['.encrypt'].value) {
          value = this[transformType](value, type, def['.encrypt'].value, true);
        }
      } else if (type === 'object' && value !== null) {
        const transformedValue = {};
        for (let key in value) {
          if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
          const subValue = value[key];
          let subDef;
          if (key.indexOf('/') >= 0) {  // for deep update keys
            const keyParts = key.split('/');
            subDef = def;
            for (i = 0; i < keyParts.length; i++) {
              if (transformType === 'decrypt') {
                keyParts[i] = this.decrypt(keyParts[i]);
                subDef = subDef && (subDef[keyParts[i]] || subDef.$);
              } else {
                subDef = subDef && (subDef[keyParts[i]] || subDef.$);
                if (subDef && subDef['.encrypt'] && subDef['.encrypt'].key) {
                  keyParts[i] =
                    this[transformType](keyParts[i], 'string', subDef['.encrypt'].key, false);
                }
              }
            }
            key = keyParts.join('/');
          } else if (transformType === 'decrypt') {
            key = this.decrypt(key);
            subDef = def[key] || def.$;
          } else {
            subDef = def[key] || def.$;
            if (subDef && subDef['.encrypt'] && subDef['.encrypt'].key) {
              key = this[transformType](key, 'string', subDef['.encrypt'].key, false);
            }
          }
          transformedValue[key] = this._transformTree(subValue, subDef, transformType);
        }
        value = transformedValue;
      } else if (type === 'array') {
        if (!def.$) return value;
        for (i = 0; i < value.length; i++) {
          value[i] = this._transformTree(value[i], def.$, transformType);
        }
      }
      return value;
    }

    refToPath(ref, encrypted) {
      const root = ref.root;
      if (ref.isEqual(root)) return [];
      const pathStr = decodeURIComponent(ref.toString().slice(root.toString().length));
      if (!encrypted && pathStr && pathStr.charAt(0) !== '.' &&
          /[\x00-\x1f\x7f\x91\x92.#$[\]]/.test(pathStr)) {  // eslint-disable-line no-control-regex
        throw new FireCryptError(`Path contains invalid characters: ${pathStr}`, 'BAD_PATH');
      }
      return pathStr.split('/');
    }

    encrypt(value, type, pattern, allowCompression) {
      const shouldCompress =
        pattern === '#' && allowCompression && type === 'string' && this._compress &&
        value.length >= this._compressionThreshold;
      if (!this._encryptString && !shouldCompress) return value;
      let cacheKey;
      if (this._encryptionCache) {
        cacheKey = type.charAt(0) + pattern + '\x91' + value;
        if (this._encryptionCache.has(cacheKey)) return this._encryptionCache.get(cacheKey);
      }
      let typeCode = type.charAt(0).toUpperCase();
      let result;
      if (pattern === '#') {
        if (shouldCompress) {
          const compressedValue = this._compress(value);
          if (!this._encryptString && typeof compressedValue === 'string') return value;
          if (this._encryptString) {
            typeCode = 'E';
            result = this.encryptValue(compressedValue, type);
          } else {
            typeCode = 'C';
            result = this._base64UrlFromU8(compressedValue);
          }
        } else {
          result = this.encryptValue(value, type);
        }
        if (result !== value) {
          result = `\x91${typeCode}${result}\x92`;
          if (this._encryptionCache) this._encryptionCache.set(cacheKey, result);
        }
      } else {
        if (type !== 'string') {
          throw new FireCryptError(`Can't encrypt a ${type} using pattern [${pattern}]`, 'BAD_VALUE');
        }
        if (!this._encryptString) return value;
        const match = value.match(this.compilePattern(pattern));
        if (!match) {
          throw new FireCryptError(
            `Can't encrypt as value doesn't match pattern [${pattern}]: ${value}`, 'BAD_VALUE');
        }
        let i = 0;
        result = pattern.replace(/[#.]/g, placeholder => {
          let part = match[++i];
          if (placeholder === '#') part = `\x91S${this.encryptValue(part, 'string')}\x92`;
          return part;
        });
      }
      return result;
    }

    encryptValue(value, type) {
      if (!/^(string|number|boolean)$/.test(type)) {
        throw new FireCryptError(`Can't encrypt a ${type}`, 'BAD_VALUE');
      }
      if (!this._encryptString) return value;
      switch (type) {
        case 'number': value = '' + value; break;
        case 'boolean': value = value ? 't' : 'f'; break;
      }
      return this._encryptString(value);
    }

    decrypt(value) {
      if (this._decryptionCache && this._decryptionCache.has(value)) {
        return this._decryptionCache.get(value);
      }
      if (!/\x91/.test(value)) return value;
      let result;
      const match = value.match(/^\x91(.)([^\x92]*)\x92$/);
      if (match) {
        if (match[1] !== 'C' && !this._decryptString) {
          throw new FireCryptError('Unable to decrypt value because encryption turned off', 'NO_KEY');
        }
        switch (match[1]) {
          case 'C':  // compressed, not encrypted string
            result = fflate.strFromU8(fflate.decompressSync(this._base64UrlToU8(match[2])));
            break;
          case 'E':  // compressed, encrypted string
            result = fflate.strFromU8(fflate.decompressSync(
              this._wordsToU8(this._decryptString(match[2], false))));
            break;
          case 'S':  // encrypted string
            result = this._decryptString(match[2], true);
            break;
          case 'N': {  // encrypted number
            const decryptionResult = this._decryptString(match[2]);
            result = Number(decryptionResult);
            // Check for NaN, since it's the only value where x !== x.
            // eslint-disable-next-line no-self-compare
            if (result !== result) {
              throw new FireCryptError(`Invalid encrypted number: ${decryptionResult}`, 'BAD_VALUE');
            }
            break;
          }
          case 'B': {  // encrypted boolean
            const decryptionResult = this._decryptString(match[2]);
            switch (decryptionResult) {
              case 't': result = true; break;
              case 'f': result = false; break;
              default:
                throw new FireCryptError(
                  `Invalid encrypted boolean: ${decryptionResult}`, 'BAD_VALUE');
            }
            break;
          }
          default:
            throw new Error(`Internal error: invalid encrypted value type code: ${match[1]}`);
        }
      } else {
        if (!this._decryptString) {
          throw new FireCryptError('Unable to decrypt value because encryption turned off', 'NO_KEY');
        }
        result = value.replace(/\x91(.)([^\x92]*)\x92/g, (ignored, typeCode, encryptedString) => {
          if (typeCode !== 'S') {
            throw new Error(`Internal error: invalid multi-segment encrypted value: ${typeCode}`);
          }
          return this._decryptString(encryptedString, true);
        });
      }
      if (this._decryptionCache) this._decryptionCache.set(value, result);
      return result;
    }

    _wordsToU8(wordArray) {
      wordArray.clamp();
      const sigBytes = wordArray.sigBytes;
      const words = wordArray.words;
      const uint8Array = new Uint8Array(sigBytes);
      for (let i = 0; i < sigBytes; i++) {
        // eslint-disable-next-line no-bitwise
        uint8Array[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      }
      return uint8Array;
    };

    getType(value) {
      if (Array.isArray(value)) return 'array';
      let type = typeof value;
      if (type === 'object') {
        if (value instanceof String) type = 'string';
        else if (value instanceof Number) type = 'number';
        else if (value instanceof Boolean) type = 'boolean';
      }
      return type;
    }

    compilePattern(pattern) {
      let regex = this._patternRegexes[pattern];
      if (!regex) {
        regex = this._patternRegexes[pattern] = new RegExp('^' + pattern
          .replace(/\./g, '#')
          .replace(/[-[\]/{}()*+?.\\^$|]/g, '\\$&')  // escape regex chars
          .replace(/#/g, '(.*?)') + '$');
      }
      return regex;
    }

    _base64UrlFromU8(bytes) {
      return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    }

    _base64UrlToU8(b64url) {
      const m = b64url.length % 4;
      return Uint8Array.from(atob(
        b64url.replace(/-/g, '+')
          .replace(/_/g, '/')
          .padEnd(b64url.length + (m === 0 ? 0 : 4 - m), '=')
      ), c => c.charCodeAt(0));
    }
  }

  class FireCryptSnapshot {
    constructor(snap, firecrypt) {
      this._ref = firecrypt._crypto.decryptRef(snap.ref);
      this._path = firecrypt._crypto.refToPath(this._ref);
      this._snap = snap;
      this._firecrypt = firecrypt;
    }

    get key() {
      return this._ref.key;
    }

    get ref() {
      return new FireCryptReference(this._ref.ref, this._firecrypt);
    }

    val() {
      return this._firecrypt._crypto.transformValue(this._path, this._snap.val(), 'decrypt');
    }

    child(childPath) {
      return new FireCryptSnapshot(this._snap.child(childPath), this._firecrypt);
    }

    forEach(action) {
      return this._snap.forEach(childSnap => {
        return action(new FireCryptSnapshot(childSnap), this._firecrypt);
      });
    }

    exists() {
      return this._snap.exists.apply(this._snap, arguments);
    }

    hasChild(childPath) {
      childPath = this._firecrypt._crypto.encryptPath(
        childPath.split('/'), this._firecrypt._crypto.specForPath(this._path)).join('/');
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
      return this._firecrypt._crypto.transformValue(this._path, json, 'decrypt');
    }
  }

  class FireCryptQuery {
    constructor(query, order, originalRef, firecrypt) {
      this._query = query;
      this._order = order || {};
      this._originalRef = originalRef || query;
      this._firecrypt = firecrypt;
    }

    _wrapQueryCallback(callback) {
      if (!callback || callback.firecryptCallback) return;
      const self = this;
      const wrappedCallback = function(snap, previousChildKey) {
        return callback.call(  // eslint-disable-next-line no-invalid-this
          this, new FireCryptSnapshot(snap, self._firecrypt), previousChildKey, self._firecrypt);
      };
      wrappedCallback.firecryptCallback = wrappedCallback;
      callback.firecryptCallback = wrappedCallback;
    }

    get ref() {
      return new FireCryptReference(
        this._firecrypt._crypto.decryptRef(this._query.ref), this._firecrypt);
    }

    /**
     * Returns a JSON-serializable representation of this object.
     * @return {Object} A JSON-serializable representation of this object.
     */
    toJSON() {
      return this._query.toJSON();
    }

    /**
     * Returns whether or not this FireCryptQuery is equivalent to the provided
     * FireCryptQuery.
     * @param {FireCryptQuery} otherQuery Another FireCryptQuery instance against which to compare.
     * @return {boolean} Whether the two queries are equivalent.
     */
    isEqual(otherQuery) {
      return this._query.isEqual(otherQuery && (otherQuery._query || otherQuery._ref));
    }

    /**
     * Stringifies the wrapped query.
     * @return {string} The Firebase URL wrapped by this FireCryptQuery object.
     */
    toString() {
      return decodeURIComponent(this._query.toString());
    }

    on(eventType, callback, cancelCallback, context) {
      this._wrapQueryCallback(callback);
      return this._originalRef.on.call(
        this._query, eventType, callback.firecryptCallback, cancelCallback, context);
    }

    off(eventType, callback, context) {
      if (callback && callback.firecryptCallback) callback = callback.firecryptCallback;
      return this._originalRef.off.call(this._query, eventType, callback, context);
    }

    once(eventType, successCallback, failureCallback, context) {
      this._wrapQueryCallback(successCallback);
      return this._originalRef.once.call(
        this._query, eventType, successCallback && successCallback.firecryptCallback, failureCallback,
        context
      ).then(snap => {
        return new FireCryptSnapshot(snap, this._firecrypt);
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
        value = this._firecrypt._crypto.encrypt(
          value, this._firecrypt._crypto.getType(value), this._order[this._order.by + 'Encrypted']);
      }
      if (key !== undefined && this._order.keyEncrypted) {
        key = this._firecrypt._crypto.encrypt(key, 'string', this._order.keyEncrypted);
      }
      return new FireCryptQuery(
        this._originalRef.equalTo.call(this._query, value, key), this._order, this._originalRef,
        this._firecrypt
      );
    }

    limitToFirst() {
      return this._delegate('limitToFirst', arguments);
    }

    limitToLast() {
      return this._delegate('limitToLast', arguments);
    }

    _delegate(methodName, args) {
      return new FireCryptQuery(
        this._originalRef[methodName].apply(this._query, args), this._order, this._originalRef,
        this._firecrypt
      );
    }

    _checkCanSort(hasExtraKey) {
      const orderedAndEncrypted = this._order.by === 'key' ?
        this._order.keyEncrypted :
        this._order.valueEncrypted || hasExtraKey && this._order.keyEncrypted;
      if (orderedAndEncrypted) throw new Error('Encrypted items cannot be ordered');
    }

    _orderBy(methodName, by, childKey) {
      const def = this._firecrypt._crypto.specForPath(this._firecrypt._crypto.refToPath(this.ref));
      const order = {by};

      let encryptedChildKey;
      if (def) {
        const childPath = childKey && childKey.split('/');
        for (const subKey in def) {
          if (!Object.prototype.hasOwnProperty.call(def, subKey)) continue;
          const subDef = def[subKey];
          if (subDef['.encrypt']) {
            if (subDef['.encrypt'].key) order.keyEncrypted = subDef['.encrypt'].key;
            if (subDef['.encrypt'].value) order.valueEncrypted = subDef['.encrypt'].value;
          }
          if (childKey) {
            const childDef = this._firecrypt._crypto.specForPath(childPath, subDef);
            if (childDef && childDef['.encrypt'] && childDef['.encrypt'].value) {
              order.childEncrypted = childDef['.encrypt'].value;
            }
            const encryptedChildKeyCandidate =
              this._firecrypt._crypto.encryptPath(childPath, subDef).join('/');
            if (encryptedChildKey && encryptedChildKeyCandidate !== encryptedChildKey) {
              throw new Error(
                'Incompatible encryption specifications for orderByChild("' + childKey + '")');
            }
            encryptedChildKey = encryptedChildKeyCandidate;
          }
        }
      }
      if (childKey) {
        return new FireCryptQuery(
          this._originalRef[methodName].call(this._query, encryptedChildKey || childKey), order,
          this._originalRef, this._firecrypt
        );
      }
      return new FireCryptQuery(
        this._originalRef[methodName].call(this._query), order, this._originalRef, this._firecrypt
      );
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

      this[methodName] = function() {
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
  if (typeof require !== 'undefined') {
    try {
      childrenKeysFromLib = require('firebase-childrenkeys');  // eslint-disable-line no-undef
    } catch {
      // Library is optional, so ignore any errors from failure to load it.
    }
  }

  class FireCryptReference {
    constructor(ref, firecrypt) {
      this._ref = ref;
      this._firecrypt = firecrypt;
    }

    _interceptQuery(methodName, originalArguments) {
      const encryptedRef = this._firecrypt._crypto.encryptRef(this._ref);
      const query = new FireCryptQuery(encryptedRef, {}, this._ref, this._firecrypt);
      return query[methodName].apply(query, originalArguments);
    }

    _interceptWrite(methodName, originalArguments, argIndex) {
      const encryptedRef = this._firecrypt._crypto.encryptRef(this._ref);

      const args = Array.prototype.slice.call(originalArguments);
      if (argIndex >= 0 && argIndex < args.length) {
        const path = this._firecrypt._crypto.refToPath(this._ref);
        args[argIndex] = this._firecrypt._crypto.transformValue(path, args[argIndex], 'encrypt');
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
      if (this._ref.isEqual(this._ref.ref)) return this;
      return new FireCryptReference(this._ref.ref, this._firecrypt);
    }

    /**
     * Returns a FireCryptReference reference to the root of the database.
     * @return {FireCryptReference} The root reference of the database.
     */
    get root() {
      if (this._ref.isEqual(this._ref.root)) return this;
      return new FireCryptReference(this._ref.root, this._firecrypt);
    }

    /**
     * Returns a FireCryptReference to the parent location of this reference. The parent of a root
     * reference is `null`.
     * @return {FireCryptReference|null} The parent location of this reference.
     */
    get parent() {
      if (this._ref.parent === null) return null;
      return new FireCryptReference(this._ref.parent, this._firecrypt);
    }

    /**
     * Returns the FireCrypt instance associated with this reference.
     * @return {FireCrypt} The FireCrypt instance associated with this reference.
     */
    get database() {
      return this._firecrypt;
    }

    /**
     * Creates a new FireCryptReference object on a child of this one.
     * @param  {string} path The path to the desired child, relative to this reference.
     * @return {FireCryptReference} The child reference.
     */
    child(path) {
      return new FireCryptReference(this._ref.child(path), this._firecrypt);
    }

    /**
     * Returns a JSON-serializable representation of this object.
     * @return {Object} A JSON-serializable representation of this object.
     */
    toJSON() {
      return this._ref.toJSON();
    }

    /**
     * Returns whether or not this FireCryptReference is equivalent to the provided
     * FireCryptReference.
     * @param {FireCryptReference} otherRef Another FireCryptReference instance against which to
     *  compare.
     * @return {boolean} Whether the two references are equivalent.
     */
    isEqual(otherRef) {
      return this._ref.isEqual(otherRef && (otherRef._ref || otherRef._query));
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
        throw new Error(
          `childrenKeys() is not implemented. You must either provide a Firebase Database Reference
        which implements childrenKeys() or npm install the firebase-children keys libary.`
        );
      }

      const encryptedRef = this._firecrypt._crypto.encryptRef(this._ref);
      return originalMethod.apply(encryptedRef, [encryptedRef, ...arguments]).then(keys => {
        if (!keys.some(key => /\x91/.test(key))) {
          return keys;
        }
        return keys.map(this._firecrypt._crypto.decrypt.bind(this._firecrypt._crypto));
      });
    }

    onDisconnect() {
      const encryptedRef = this._firecrypt._crypto.encryptRef(this._ref);
      return new FireCryptOnDisconnect(
        encryptedRef, this._ref.onDisconnect.call(encryptedRef), this._crypto);
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
      const encryptedRef = this._firecrypt._crypto.encryptRef(this._ref);
      const path = this._firecrypt._crypto.refToPath(this._ref);

      const args = Array.prototype.slice.call(arguments);
      const originalCompute = args[0];
      args[0] = originalCompute && (value => {
        value = this._firecrypt._crypto.transformValue(path, value, 'decrypt');
        value = originalCompute(value);
        value = this._firecrypt._crypto.transformValue(path, value, 'encrypt');
        return value;
      });
      if (args.length > 1) {
        const originalOnComplete = args[1];
        args[1] = originalOnComplete && ((error, committed, snapshot) => {
          return originalOnComplete(
            error, committed, snapshot && new FireCryptSnapshot(snapshot, this._firecrypt));
        });
      }
      return this._ref.transaction.apply(encryptedRef, args).then(result => {
        result.snapshot =
          result.snapshot && new FireCryptSnapshot(result.snapshot, this._firecrypt);
        return result;
      });
    }
  }

  if (typeof require !== 'undefined') {
    /* eslint-disable no-undef */
    if (typeof fflate === 'undefined') global.fflate = require('fflate');
    if (typeof LRUCache === 'undefined') global.LRUCache = require('lru-cache');
    if (typeof CryptoJS === 'undefined') global.CryptoJS = require('crypto-js/core');
    require('crypto-js/lib-typedarrays');
    require('crypto-js/enc-base64');
    require('crypto-js/enc-base64url');
    require('cryptojs-extension/build_node/siv');
    /* eslint-enable no-undef */
  }

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


  function wrapDatabase(database) {
    const fc = new FireCrypt(database);
    if (database.getRules) {
      fc.getRules = () => database.getRules();
      fc.getRulesJSON = () => database.getRulesJSON();
      fc.setRules = source => database.setRules(source);
    }
    return fc;
  }

  exports.wrapDatabase = wrapDatabase;

  return exports;

})({});
//# sourceMappingURL=firecrypt.js.map
