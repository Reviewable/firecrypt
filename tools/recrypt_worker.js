'use strict';

const _ = require('lodash');
const NodeFire = require('nodefire').default;
const LRUCache = require('lru-cache');
const fflate = require('fflate');

const CryptoJS = require('crypto-js/core');
require('crypto-js/lib-typedarrays');
require('crypto-js/enc-base64');
require('crypto-js/enc-base64url');
require('cryptojs-extension/build_node/siv');

const ALREADY_RECRYPTED = {};
const CACHE_SIZE = 10 * 1000 * 1000;

const caches = {
  encryptNew: new LRUCache({max: CACHE_SIZE, length: computeCacheItemSize}),
  encryptOld: new LRUCache({max: CACHE_SIZE, length: computeCacheItemSize}),
  decrypt: new LRUCache({max: CACHE_SIZE, length: computeCacheItemSize})
};
_.forEach(caches, cache => {cache.stats = {hits: 0, misses: 0};});

let oldSiv, newSiv, spec;
let numCalls = 0;
_.assign(exports, {traverseWildcard, traverseSpec, traverseSmall, transformSmall});

process.on('message', msg => {
  switch (msg.cmd) {
    case 'init':
      oldSiv = msg.oldKey && CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(msg.oldKey));
      newSiv = msg.newKey && CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(msg.newKey));
      spec = msg.spec;
      break;
    case 'call':
      if (++numCalls % 1000 === 0) {
        process.send({cmd: 'stats', stats: _.mapValues(caches, 'stats')});
      }
      exports[msg.fn].apply(null, msg.args);
      process.send({cmd: 'ready'});
      break;
    default:
      throw new Error('Invalid message from master: ' + msg.cmd);
  }
});

function callMaster() {
  process.send({cmd: 'call', fn: arguments[0], args: _.slice(arguments, 1)});
}

function traverseWildcard(specPath, oldPath, newPath, copy, keys) {
  const def = defForPath(specPath);
  _.forEach(keys, oldKey => {
    const key = decrypt(oldKey);
    if (key === ALREADY_RECRYPTED) return;
    const subDef = def[key] || def.$;
    const keyFlags = subDef['.encrypt'] || {};
    const subCopy = copy || keyFlags.key || keyFlags.value;
    if (!subCopy && !keyFlags.children) return;
    const newKey = keyFlags.key ? encrypt(key, keyFlags.key) : key;
    const subSpecPath = join(specPath, def[key] ? key : '$');
    const subOldPath = join(oldPath, oldKey);
    const subNewPath = join(newPath, newKey);
    if ((!subCopy || keyFlags.big) && !subDef.$) {
      traverseSpec(subSpecPath, subOldPath, subNewPath, subCopy);
    } else {
      callMaster('traverse', subSpecPath, subOldPath, subNewPath, subCopy);
    }
  });
}

function traverseSpec(specPath, oldPath, newPath, copy) {
  const def = defForPath(specPath);
  _.forEach(_.keys(def), key => {
    if (key === '.encrypt') return;
    const keyFlags = def[key]['.encrypt'] || {};
    const subCopy = copy || keyFlags.key || keyFlags.value;
    if (!subCopy && !keyFlags.children) return;
    const oldKey = NodeFire.escape(keyFlags.key ? encrypt(key, keyFlags.key, true) : key);
    const newKey = NodeFire.escape(keyFlags.key ? encrypt(key, keyFlags.key) : key);
    const subSpecPath = join(specPath, key);
    const subOldPath = join(oldPath, oldKey);
    const subNewPath = join(newPath, newKey);
    if ((!subCopy || keyFlags.big) && !def[key].$) {
      traverseSpec(subSpecPath, subOldPath, subNewPath, subCopy);
    } else {
      callMaster('traverse', subSpecPath, subOldPath, subNewPath, subCopy);
    }
  });
}

function traverseSmall(specPath, oldPath, newPath, value) {
  const def = defForPath(specPath);
  const flags = def['.encrypt'] || {};
  if (flags.children) {
    _.forEach(_.keys(value), oldKey => {
      const key = decrypt(oldKey);
      if (key === ALREADY_RECRYPTED) return;
      const subDef = def[key] || def.$;
      if (!subDef) return;
      const subFlags = subDef['.encrypt'] || {};
      if (!(subFlags.key || subFlags.value || subFlags.children)) return;
      const newKey = subFlags.key ? encrypt(key, subFlags.key) : key;
      const subOldPath = join(oldPath, oldKey), subNewPath = join(newPath, newKey);
      traverseSmall(join(specPath, def[key] ? key : '$'), subOldPath, subNewPath, value[oldKey]);
    });
  } else if (flags.key || flags.value) {
    transformSmall(specPath, oldPath, newPath, value);
  }
}

function transformSmall(specPath, oldPath, newPath, value) {
  const def = defForPath(specPath);
  const newValue = transformSmallHelper(def, value);
  if (oldPath !== newPath || newValue !== ALREADY_RECRYPTED) {
    const updates = {[newPath]: newValue === ALREADY_RECRYPTED ? value : newValue};
    if (newPath !== oldPath) updates[oldPath] = null;
    callMaster('queueUpdates', updates);
  }
}

function transformSmallHelper(def, value) {
  const flags = def['.encrypt'] || {};
  if (flags.children) {
    let allAlreadyRecrypted = true;
    _.forEach(_.keys(value), oldKey => {
      const key = decrypt(oldKey);
      if (key === ALREADY_RECRYPTED) return;
      const subDef = def[key] || def.$;
      if (!subDef) return;
      const subFlags = subDef['.encrypt'];
      if (!subFlags) return;
      if (subFlags.value || subFlags.children) {
        const newValue = transformSmallHelper(subDef, value[oldKey]);
        if (newValue !== ALREADY_RECRYPTED) {
          value[oldKey] = newValue;
          allAlreadyRecrypted = false;
        }
      }
      const newKey = subFlags.key ? encrypt(key, subFlags.key) : key;
      if (newKey !== oldKey) {
        value[newKey] = value[oldKey];
        delete value[oldKey];
        allAlreadyRecrypted = false;
      }
    });
    if (allAlreadyRecrypted) value = ALREADY_RECRYPTED;
  } else if (flags.value) {
    const newValue = decrypt(value);
    if (newValue === value && !newSiv) {
      value = ALREADY_RECRYPTED;
    } else if (newValue !== ALREADY_RECRYPTED && newSiv) {
      value = encrypt(newValue, flags.value);
    } else {
      value = newValue;
    }
  }
  return value;
}

function decrypt(value) {
  if (!(_.isString(value) && /\x91/.test(value))) return value;
  if (caches.decrypt.has(value)) {
    caches.decrypt.stats.hits += 1;
    return caches.decrypt.get(value);
  }
  caches.decrypt.stats.misses += 1;
  let result;
  const match = value.match(/^\x91(.)([^\x92]*)\x92$/);
  if (match) {
    const decryptedString = decryptOldString(match[2]);
    if (decryptedString === ALREADY_RECRYPTED) {
      result = ALREADY_RECRYPTED;
    } else {
      switch (match[1]) {
        case 'C':
          result = fflate.strFromU8(fflate.decompressSync(Buffer.from(match[2], 'base64url')));
          break;
        case 'E':
          result =
            fflate.strFromU8(fflate.decompressSync(wordsToU8(decryptOldString(match[2], false))));
          break;
        case 'S':
          result = decryptOldString(match[2], true);
          break;
        case 'N': {
          const decryptedString = decryptOldString(match[2], true);
          result = Number(decryptedString);
          // Check for NaN, since it's the only value where x !== x.
          // eslint-disable-next-line no-self-compare
          if (result !== result) throw new Error('Invalid encrypted number: ' + decryptedString);
          break;
        }
        case 'B': {
          const decryptedString = decryptOldString(match[2], true);
          if (decryptedString === 't') result = true;
          else if (decryptedString === 'f') result = false;
          else throw new Error('Invalid encrypted boolean: ' + decryptedString);
          break;
        }
        default:
          throw new Error('Invalid encrypted value type code: ' + match[1]);
      }
    }
  } else {
    let allOld = true, allNew = true;
    result = value.replace(/\x91(.)([^\x92]*)\x92/g, (ignore, typeCode, encryptedString) => {
      if (typeCode !== 'S') throw new Error('Invalid multi-segment encrypted value: ' + typeCode);
      const decryptedString = decryptOldString(encryptedString);
      if (decryptedString === ALREADY_RECRYPTED) {
        allOld = false;
        return encryptedString;
      }
      allNew = false;
      return decryptedString;
    });
    if (allNew) result = ALREADY_RECRYPTED;
    else if (!allOld) throw new Error('Patterned value partially recrypted');
  }
  caches.decrypt.set(value, result);
  return result;
}

function encrypt(value, pattern, old) {
  const siv = old ? oldSiv : newSiv;
  if (!siv) return value;
  const cache = old ? caches.encryptOld : caches.encryptNew;
  const type = getType(value);
  const cacheKey = type.charAt(0) + pattern + '\x91' + value;
  if (cache.has(cacheKey)) {
    cache.stats.hits += 1;
    return cache.get(cacheKey);
  }
  cache.stats.misses += 1;
  // TODO: compress while re-encrypting, if requested by user.
  let result;
  if (pattern === '#') {
    result = encryptValue(value, type, siv);
  } else {
    if (type !== 'string') {
      throw new Error('Can\'t encrypt a ' + type + ' using pattern [' + pattern + ']');
    }
    const match = value.match(compilePattern(pattern));
    if (!match) {
      throw new Error(
        'Can\'t encrypt as value doesn\'t match pattern [' + pattern + ']: ' + value);
    }
    let i = 0;
    result = pattern.replace(/[#.]/g, placeholder => {
      let part = match[++i];
      if (placeholder === '#') part = encryptValue(part, 'string', siv);
      return part;
    });
  }
  cache.set(cacheKey, result);
  return result;
}

function decryptOldString(str, decode) {
  let result = oldSiv ? oldSiv.decrypt(CryptoJS.enc.Base64url.parse(str)) : false;
  if (result === false) {
    result = newSiv ? newSiv.decrypt(CryptoJS.enc.Base64url.parse(str)) : false;
    if (result !== false) return ALREADY_RECRYPTED;
    const e = new Error('Wrong decryption key');
    e.firecrypt = 'WRONG_KEY';
    throw e;
  }
  return decode ? CryptoJS.enc.Utf8.stringify(result) : result;
}

function encryptValue(value, type, siv) {
  switch (type) {
    case 'number': value = '' + value; break;
    case 'boolean': value = value ? 't' : 'f'; break;
  }
  return '\x91' + _.toUpper(type.charAt(0)) + encryptString(value, siv) + '\x92';
}

function encryptString(str, siv) {
  return CryptoJS.enc.Base64url.stringify(siv.encrypt(str));
}

function getType(value) {
  if (_.isArray(value)) return 'array';
  let type = typeof value;
  if (type === 'object') {
    if (value instanceof String) type = 'string';
    else if (value instanceof Number) type = 'number';
    else if (value instanceof Boolean) type = 'boolean';
  }
  return type;
}

const patternRegexes = {};
function compilePattern(pattern) {
  let regex = patternRegexes[pattern];
  if (!regex) {
    regex = patternRegexes[pattern] = new RegExp('^' + pattern
      .replace(/\./g, '#')
      .replace(/[-[\]/{}()*+?.\\^$|]/g, '\\$&')  // escape regex chars
      .replace(/#/g, '(.*?)') + '$');
  }
  return regex;
}

function join() {
  return _(arguments).toArray().compact().join('/');
}

function defForPath(path) {
  if (!path) return spec;
  return _.reduce(path.split('/'), (def, segment) => def[segment], spec);
}

function computeCacheItemSize(value, key) {
  return key.length + (_.isString(value) ? value.length : 4);
}

function wordsToU8(wordArray) {
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

