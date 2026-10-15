'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {wrapDatabase} = require('../dist/node/firecrypt');
const CryptoJS = require('crypto-js');

const key = Buffer.alloc(32, 0x42).toString('base64');
const otherKey = Buffer.alloc(32, 0x24).toString('base64');
const encryptWith = encryptionKey => {
  const siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(encryptionKey));
  return value => '\x91S' + CryptoJS.enc.Base64url.stringify(siv.encrypt(value)) + '\x92';
};
const encrypt = encryptWith(key);
const encryptOther = encryptWith(otherKey);

// A stub database that records which location each listener call was made on, so that a test can
// check that `off` addresses the same encrypted location `on` did.
function createDatabase() {
  const calls = [];

  class Reference {
    constructor(parts = []) {
      this.parts = parts;
    }

    get root() {
      return new Reference();
    }

    child(path) {
      return new Reference([...this.parts, ...path.split('/').filter(Boolean)]);
    }

    isEqual(other) {
      return this.toString() === other.toString();
    }

    toString() {
      return 'https://firecrypt.test/' + this.parts.map(encodeURIComponent).join('/');
    }

    on(eventType, callback, cancelCallback, context) {
      calls.push(
        {method: 'on', path: this.parts.join('/'), eventType, callback, cancelCallback, context});
      return callback;
    }

    off(eventType, callback) {
      calls.push({method: 'off', path: this.parts.join('/'), eventType, callback});
    }
  }

  const database = wrapDatabase({app: {}, ref: (path = '') => new Reference().child(path)});
  // `encryptionKey` undefined means the key has been released.
  const configure = encryptionKey => database.configureFireCrypt(
    {encryption: encryptionKey ? 'aes-siv' : 'notready', compression: 'none', key: encryptionKey},
    {rules: {records: {$record: {'.encrypt': {key: '#'}}}}}
  );
  configure(key);
  const summarize = () => calls.map(({method, path}) => `${method} ${path}`);
  return {database, calls, configure, summarize};
}

const path = 'records/' + encrypt('person');
const otherPath = 'records/' + encryptOther('person');

test('off on the reference that added a listener works after the key is released', () => {
  const {database, calls, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const callback = () => undefined;
  ref.on('value', callback);

  configure(undefined);
  assert.throws(() => database.ref('records/person').off('value', callback), {firecrypt: 'NO_KEY'});
  ref.off('value', callback);

  assert.deepEqual(summarize(), [`on ${path}`, `off ${path}`]);
  assert.equal(calls[1].callback, calls[0].callback, 'off must remove the wrapped callback');
});

test('the callback returned by on removes the listener after the key is released', () => {
  const {database, calls, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const handle = ref.on('value', () => undefined);

  configure(undefined);
  ref.off('value', handle);

  assert.deepEqual(summarize(), [`on ${path}`, `off ${path}`]);
  assert.equal(calls[1].callback, calls[0].callback);
});

test('off without a callback still needs the key', () => {
  const {database, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  ref.on('value', () => undefined);

  configure(undefined);
  assert.throws(() => ref.off(), {firecrypt: 'NO_KEY'});
  assert.throws(() => ref.off('value'), {firecrypt: 'NO_KEY'});

  assert.deepEqual(summarize(), [`on ${path}`]);
});

test('with the key available, off addresses where the path encrypts to now', () => {
  const {database, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const first = () => undefined;
  const second = () => undefined;
  ref.on('value', first);
  ref.off('value', first);
  configure(otherKey);
  database.ref('records/person').on('value', second);

  ref.off('value', second);

  assert.deepEqual(summarize(), [
    `on ${path}`, `off ${path}`, `on ${otherPath}`, `off ${otherPath}`
  ]);
});

test('off on a fresh reference still encrypts the path', () => {
  const {database, calls, summarize} = createDatabase();
  const callback = () => undefined;
  database.ref('records/person').on('value', callback);
  database.ref('records/person').off('value', callback);

  assert.deepEqual(summarize(), [`on ${path}`, `off ${path}`]);
  assert.equal(calls[1].callback, calls[0].callback);
});

// Another reference may have added the same callback again under the new key, which removing it
// from the old location would leave behind while reporting success.
test('off after the key changed since the reference listened still needs the key', () => {
  const {database, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const callback = () => undefined;
  ref.on('value', callback);
  ref.off('value', callback);
  configure(otherKey);
  database.ref('records/person').on('value', callback);

  configure(undefined);
  assert.throws(() => ref.off('value', callback), {firecrypt: 'NO_KEY'});

  assert.deepEqual(summarize(), [`on ${path}`, `off ${path}`, `on ${otherPath}`]);
});

test('reinstalling the same key keeps the keyless fallback working', () => {
  const {database, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const callback = () => undefined;
  ref.on('value', callback);
  configure(undefined);
  configure(key);

  configure(undefined);
  ref.off('value', callback);

  assert.deepEqual(summarize(), [`on ${path}`, `off ${path}`]);
});
