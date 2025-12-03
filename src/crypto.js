import FireCryptError from './FireCryptError';

export default class Crypto {
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
