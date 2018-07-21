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
      var subValue = value[key], subDef;
      if (key.indexOf('/') >= 0) {  // for deep update keys
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
  if (!encrypted && pathStr && pathStr.charAt(0) !== '.' &&
      /[\x00-\x1f\x7f\x91\x92\.#$\[\]]/.test(pathStr)) {
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
      throw new Error(
        'Can\'t encrypt as value doesn\'t match pattern [' + pattern + ']: ' + value);
    }
    var i = 0;
    result = pattern.replace(/[#\.]/g, function(placeholder) {
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
    case 'number': value = '' + value; break;
    case 'boolean': value = value ? 't' : 'f'; break;
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
        if (decryptedString === 't') result = true;
        else if (decryptedString === 'f') result = false;
        else throw new Error('Invalid encrypted boolean: ' + decryptedString);
        break;
      default:
        throw new Error('Invalid encrypted value type code: ' + match[1]);
    }
  } else {
    result = value.replace(/\x91(.)([^\x92]*)\x92/g, function(match, typeCode, encryptedString) {
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
    if (value instanceof String) type = 'string';
    else if (value instanceof Number) type = 'number';
    else if (value instanceof Boolean) type = 'boolean';
  }
  return type;
}

var patternRegexes = {};
function compilePattern(pattern) {
  var regex = patternRegexes[pattern];
  if (!regex) {
    regex = patternRegexes[pattern] = new RegExp('^' + pattern
      .replace(/\./g, '#')
      .replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&')  // escape regex chars
      .replace(/#/g, '(.*?)') + '$');
  }
  return regex;
}

module.exports = {
  setSpec,
  encrypt,
  decrypt,
  getType,
  refToPath,
  decryptRef,
  encryptRef,
  encryptPath,
  specForPath,
  encryptValue,
  transformTree,
  transformValue,
  compilePattern,
  setEncryptionCache,
  setDecryptionCache,
  throwNotSetUpError,
  computeCacheItemSize,
}
