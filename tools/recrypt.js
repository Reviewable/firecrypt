#!/usr/bin/env node
'use strict';

const _ = require('lodash');
const co = require('co');
const commandLineArgs = require('command-line-args');
const fs = require('mz/fs');
const getUsage = require('command-line-usage');
const HttpsAgent = require('agentkeepalive').HttpsAgent;
const ms = require('ms');
const NodeFire = require('nodefire');
const request = require('request');

const CryptoJS = require('crypto-js/core');
require('crypto-js/enc-base64');
require('cryptojs-extension/build_node/siv');

const ALREADY_RECRYPTED = {};

CryptoJS.enc.Base64UrlSafe = {
  stringify: CryptoJS.enc.Base64.stringify,
  parse: CryptoJS.enc.Base64.parse,
  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
};

NodeFire.setCacheSize(0);

const agent = new HttpsAgent({
  keepAliveMsecs: ms('1s'), keepAliveTimeout: ms('15s'), timeout: ms('30s'), maxSockets: 3,
  maxFreeSockets: 1
});

const commandLineOptions = [
  {name: 'firebase', alias: 'f',
   typeLabel: '[underline]{database}',
   description: 'The unique id of the target realtime database (required).'},
  {name: 'auth', alias: 'a',
   typeLabel: '[underline]{secret}',
   description: 'A master secret to authenticate with for the target database (required).'},
  {name: 'spec', alias: 's',
   typeLabel: '[underline]{file}',
   description: 'The firecrypt rules JSON file (required).'},
  {name: 'oldKey', alias: 'o',
   typeLabel: '[underline]{base64key}',
   description: 'The old encryption key to be replaced.'},
  {name: 'newKey', alias: 'n',
   typeLabel: '[underline]{base64key}',
   description: 'The new encryption key to use.'},
  {name: 'help', alias: 'h',
   description: 'Display these usage instructions.'},
  {name: 'verbose', alias: 'v',
   description: 'Turn on verbose logging messages for debugging'}
];

const usageSpec = [
  {header: 'Encryption key rotation tool',
   content:
    'Changes the encryption key of a Firebase database that has been encrypted with firecrypt. ' +
    'It can also remove the encryption altogether, or add it to an unencrypted database.\n\n' +
    'You should ensure that nobody accesses the database while the keys are being rotated.'
  },
  {header: 'Options', optionList: commandLineOptions}
];


const args = commandLineArgs(commandLineOptions);
if (args.help) {
  console.log(getUsage(usageSpec));
  process.exit(0);
}
try {
  for (let property of ['firebase', 'auth', 'spec']) {
    if (!(property in args)) throw new Error('Missing required option: ' + property + '.');
  }
  if (!('oldKey' in args || 'newKey' in args)) {
    throw new Error('Need to specify at least one of oldKey and newKey.');
  }
} catch (e) {
  console.log(e.toString());
  console.log(getUsage(usageSpec));
  process.exit(1);
}

const firebaseUrl = 'https://' + args.firebase + '.firebaseio.com';
const firebaseAuth = args.auth;
const db = new NodeFire(firebaseUrl);
const oldSiv = args.oldKey && CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(args.oldKey));
const newSiv = args.newKey && CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(args.newKey));

const MAX_UPDATES_SIZE = 1000, MAX_UPDATES_IN_FLIGHT = 10, MAX_UPDATE_TRIES = 5;
let updatesBatch = {}, updatesBatchSize = 0, allUpdatesPromise = Promise.resolve();
const runningUpdatePromises = [];

const pace = args.verbose ? {total: 0, op: () => null} : require('pace')(1);

co(function*() {
  const results = yield [
    db.auth(firebaseAuth),
    fs.readFile(args.spec)
  ];
  const spec = expandSpecification(JSON.parse(results[1]));
  // console.log(JSON.stringify(spec, null, 2));
  yield traverse(spec.rules, '', '');
  flushUpdates();
  pace.op();
  yield allUpdatesPromise;
}).then(() => {
  process.exit(0);
}, e => {
  console.log(e.stack);
  process.exit(1);
});


function expandSpecification(def, path) {
  const flags = def['.encrypt'] || {};
  _.each(_.keys(def), key => {
    if (key === '.encrypt') {
      const badSubKeys = _.reject(
        _.keys(def[key]), subKey => _.includes(['key', 'value', 'few', 'big', 'children'], subKey));
      if (badSubKeys.length) throw new Error('Illegal .encrypt subkeys: ' + badSubKeys.join(', '));
    } else {
      if (key.charAt(0) === '.') throw new Error('Unknown directive at ' + path + ': ' + key);
      if (/[\x00-\x1f\x7f\x91\x92\.#\[\]/]/.test(key) || /[$]/.test(key.slice(1))) {
        throw new Error('Illegal character in specification key: ' + key);
      }
      expandSpecification(def[key], (path || '') + '/' + key);
      const subEncrypt = def[key]['.encrypt'];
      if (subEncrypt) {
        if (subEncrypt.children || subEncrypt.key || subEncrypt.value) flags.children = true;
        if (subEncrypt.big) flags.big = true;
      }
      if (key.charAt(0) === '$') {
        if (!(subEncrypt && subEncrypt.few)) flags.big = true;
        if (def.$) throw new Error('Multiple wildcard keys in specification at ' + path);
        def.$ = def[key];
        delete def[key];
      }
    }
  });
  if (!def['.encrypt'] && !_.isEmpty(flags)) def['.encrypt'] = flags;
  return def;
}

function *traverse(def, oldPath, newPath, copy) {
  try {
    const flags = def['.encrypt'] || {};
    copy = copy || flags.key || flags.value;
    if (!(flags.children || copy)) return;
    if (copy && !flags.big) {
      pace.total += 1;
      const leaf = yield db.child(oldPath).get();
      pace.op();
      if (leaf) transformSmall(leaf, def, oldPath, newPath);
    } else {
      if (def.$) {
        if (flags.big) {
          yield traverseWildcard(def, oldPath, newPath, copy);
        } else {
          // !flags.big && !copy
          pace.total += 1;
          const leaf = yield db.child(oldPath).get();
          pace.op();
          if (leaf) traverseSmall(leaf, def, oldPath, newPath);
        }
      } else {
        yield traverseSpec(def, oldPath, newPath, copy);
      }
    }
  } catch (e) {
    e.oldPath = oldPath;
    e.newPath = newPath;
    throw e;
  }
}

function *traverseWildcard(def, oldPath, newPath, copy) {
  log('traverseWildcard', oldPath);
  const keys = yield requestKeys(oldPath);
  yield _.map(keys, oldKey => {
    const key = decrypt(oldKey);
    if (key === ALREADY_RECRYPTED) return Promise.resolve();
    const keyFlags = (def[key] || def.$ || {})['.encrypt'] || {};
    const newKey = keyFlags.key ? encrypt(key, keyFlags.key) : key;
    return traverse(def[key] || def.$, join(oldPath, oldKey), join(newPath, newKey), copy);
  });
}

function *traverseSpec(def, oldPath, newPath, copy) {
  log('traverseSpec', oldPath);
  yield _.map(_.keys(def), key => {
    const keyFlags = def[key]['.encrypt'] || {};
    const oldKey = keyFlags.key ? encrypt(key, keyFlags.key, oldSiv) : key;
    const newKey = keyFlags.key ? encrypt(key, keyFlags.key) : key;
    return traverse(def[key], join(oldPath, oldKey), join(newPath, newKey), copy);
  });
}

function transformSmall(value, def, oldPath, newPath) {
  log('transformSmall', oldPath);
  const newValue = transformSmallHelper(value, def);
  if (oldPath !== newPath || newValue !== ALREADY_RECRYPTED) {
    const updates = {[newPath]: newValue === ALREADY_RECRYPTED ? value : newValue};
    if (newPath !== oldPath) updates[oldPath] = null;
    queueUpdates(updates);
  }
}

function transformSmallHelper(value, def) {
  const flags = def['.encrypt'] || {};
  if (flags.children) {
    let allAlreadyRecrypted = true;
    _.each(_.keys(value), oldKey => {
      const key = decrypt(oldKey);
      if (key === ALREADY_RECRYPTED) return;
      const subDef = def[key] || def.$;
      if (!subDef) return;
      const subFlags = subDef['.encrypt'];
      if (!subFlags) return;
      if (subFlags.value || subFlags.children) {
        const newValue = transformSmallHelper(value[oldKey], subDef);
        if (newValue !== ALREADY_RECRYPTED) {
          value[oldKey] = newValue;
          allAlreadyRecrypted = false;
        }
      }
      const newKey = subFlags.key ? encrypt(key) : key;
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

function traverseSmall(value, def, oldPath, newPath) {
  log('traverseSmall', oldPath);
  const flags = def['.encrypt'] || {};
  if (flags.children) {
    _.each(_.keys(value), oldKey => {
      const key = decrypt(oldKey);
      if (key === ALREADY_RECRYPTED) return;
      const subDef = def[key] || def.$;
      if (!subDef) return;
      const subFlags = subDef['.encrypt'] || {};
      if (!(subFlags.key || subFlags.value || subFlags.children)) return;
      const newKey = subFlags.key ? encrypt(key, subFlags.key) : key;
      const subOldPath = join(oldPath, oldKey), subNewPath = join(newPath, newKey);
      traverseSmall(value[oldKey], subDef, subOldPath, subNewPath);
    });
  } else if (flags.key || flags.value) {
    transformSmall(value, def, oldPath, newPath);
  }
}

function queueUpdates(updates) {
  log('queueUpdates', updates);
  const size = estimateUpdatesSize(updates);
  if (size >= MAX_UPDATES_SIZE) {
    // send it out by itself
    return;
  } else if (updatesBatchSize + size > MAX_UPDATES_SIZE) {
    flushUpdates();
  }
  _.extend(updatesBatch, updates);
  updatesBatchSize += size;
}

function flushUpdates() {
  if (_.isEmpty(updatesBatch)) return;
  log('flushUpdates', updatesBatchSize);
  const updates = updatesBatch;
  updatesBatch = {};
  updatesBatchSize = 0;
  pace.total += 1;

  allUpdatesPromise = allUpdatesPromise.then(() => {
    if (runningUpdatePromises.length >= MAX_UPDATES_IN_FLIGHT) {
      return Promise.race(runningUpdatePromises);
    }
    let tries = 1;
    const promise = db.update(updates).catch(e => {
      if (tries < MAX_UPDATE_TRIES) {
        console.log('Retrying update due to', e.toString());
        tries++;
        return db.update(updates);
      }
      console.log(updates);
      console.log('Update failed', tries, 'times, aborting');
      process.exit(1);
    }).then(() => {
      _.pull(runningUpdatePromises, promise);
      pace.op();
    });
    runningUpdatePromises.push(promise);
    return promise;
  });
}

function estimateUpdatesSize(object) {
  if (!_.isObject(object)) return 0;
  let size = 0;
  _.each(object, value => {size += estimateUpdatesSize(value);});
  size += _.size(object);
  return size;
}

function decrypt(value) {
  if (!(_.isString(value) && /\x91/.test(value))) return value;
  const match = value.match(/^\x91(.)([^\x92]*)\x92$/);
  if (match) {
    const decryptedString = decryptOldString(match[2]);
    if (decryptedString === ALREADY_RECRYPTED) return ALREADY_RECRYPTED;
    switch (match[1]) {
      case 'S':
        value = decryptedString;
        break;
      case 'N':
        value = Number(decryptedString);
        // Check for NaN, since it's the only value where x !== x.
        if (value !== value) throw new Error('Invalid encrypted number: ' + decryptedString);
        break;
      case 'B':
        if (decryptedString === 't') value = true;
        else if (decryptedString === 'f') value = false;
        else throw new Error('Invalid encrypted boolean: ' + decryptedString);
        break;
      default:
        throw new Error('Invalid encrypted value type code: ' + match[1]);
    }
  } else {
    let allOld = true, allNew = true;
    value = value.replace(/\x91(.)([^\x92]*)\x92/g, function(match, typeCode, encryptedString) {
      if (typeCode !== 'S') throw new Error('Invalid multi-segment encrypted value: ' + typeCode);
      const decryptedString = decryptOldString(encryptedString);
      if (decryptedString === ALREADY_RECRYPTED) {
        allOld = false;
        return encryptedString;
      } else {
        allNew = false;
        return decryptedString;
      }
    });
    if (allNew) return ALREADY_RECRYPTED;
    if (!allOld) throw new Error('Patterned value partially recrypted');
  }
  return value;
}

function encrypt(value, pattern, siv) {
  siv = siv || newSiv;
  if (!siv) return value;
  var type = getType(value);
  if (pattern === '#') {
    value = encryptValue(value, type, siv);
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
    value = pattern.replace(/[#\.]/g, function(placeholder) {
      let part = match[++i];
      if (placeholder === '#') part = encryptValue(part, 'string', siv);
      return part;
    });
  }
  return value;
}

function decryptOldString(str) {
  let result = oldSiv ? oldSiv.decrypt(CryptoJS.enc.Base64UrlSafe.parse(str)) : false;
  if (result === false) {
    result = newSiv ? newSiv.decrypt(CryptoJS.enc.Base64UrlSafe.parse(str)) : false;
    if (result !== false) return ALREADY_RECRYPTED;
    var e = new Error('Wrong decryption key');
    e.firecrypt = 'WRONG_KEY';
    throw e;
  }
  return CryptoJS.enc.Utf8.stringify(result);
}

function encryptValue(value, type, siv) {
  if (!/^(string|number|boolean)$/.test(type)) throw new Error('Can\'t encrypt a ' + type);
  switch (type) {
    case 'number': value = '' + value; break;
    case 'boolean': value = value ? 't' : 'f'; break;
  }
  return '\x91' + type.charAt(0).toUpperCase() + encryptString(value, siv) + '\x92';
}

function encryptString(str, siv) {
  return CryptoJS.enc.Base64UrlSafe.stringify(siv.encrypt(str));
}

function getType(value) {
  if (Array.isArray(value)) return 'array';
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
      .replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&')  // escape regex chars
      .replace(/#/g, '(.*?)') + '$');
  }
  return regex;
}

function requestKeys(path) {
  pace.total += 1;
  return new Promise((resolve, reject) => {
    let tries = 0;
    const uriPath =
      '/' + _(path.split('/')).compact().map(part => encodeURIComponent(part)).join('/');
    const req = () => request(
      {uri: firebaseUrl + uriPath + '.json', qs: {auth: firebaseAuth, shallow: true}, agent: agent},
      (error, response, data) => {
        if (!error) {
          try {
            resolve(_(JSON.parse(data)).keys().map(decode).value());
            pace.op();
            return;
          } catch (e) {
            error = e;
          }
        }
        if (++tries <= 3) req(); else {pace.op(); reject(error);}
      }
    );
    req();
  });
}

function join() {
  return _(arguments).toArray().compact().join('/');
}

function decode(string) {
  return string.replace(/\\../g, function(match) {
    return String.fromCharCode(parseInt(match.slice(1), 16));
  });
}

function log() {
  if (args.verbose) console.log.apply(console, arguments);
}

