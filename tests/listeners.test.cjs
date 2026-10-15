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

test('off on a fresh reference still encrypts the path', () => {
  const {database, calls, summarize} = createDatabase();
  const callback = () => undefined;
  database.ref('records/person').on('value', callback);
  database.ref('records/person').off('value', callback);

  assert.deepEqual(summarize(), [`on ${path}`, `off ${path}`]);
  assert.equal(calls[1].callback, calls[0].callback);
});

test('each listener is removed where it was added, across key changes', () => {
  const {database, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const first = () => undefined;
  const second = () => undefined;
  ref.on('value', first);
  configure(otherKey);
  ref.on('value', second);

  configure(undefined);
  ref.off('value', first);
  ref.off('value', second);

  assert.deepEqual(summarize(), [
    `on ${path}`, `on ${otherPath}`, `off ${path}`, `off ${otherPath}`
  ]);
});

test('a listener added through an equivalent reference is removed where it was added', () => {
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

test('off without a callback clears every location the reference listened at', () => {
  const {database, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  ref.on('value', () => undefined);
  ref.on('value', () => undefined);
  configure(otherKey);
  ref.on('value', () => undefined);

  ref.off('value');

  assert.deepEqual(summarize().slice(3), [`off ${path}`, `off ${otherPath}`]);
});

test('off without a callback still clears the reference\'s own listeners without the key', () => {
  const {database, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  ref.on('value', () => undefined);

  configure(undefined);
  ref.off();
  assert.deepEqual(summarize().slice(1), [`off ${path}`]);

  assert.throws(() => database.ref('records/person').off(), {firecrypt: 'NO_KEY'});
});

test('off removes one registration of a callback added more than once', () => {
  const {database, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const callback = () => undefined;
  ref.on('value', callback);
  ref.on('value', callback);

  ref.off('value', callback);
  assert.deepEqual(summarize().slice(2), [`off ${path}`]);

  ref.off('value', callback);
  assert.deepEqual(summarize().slice(2), [`off ${path}`, `off ${path}`]);
});

test('a listener Firebase cancelled is no longer removed where it was added', () => {
  const {database, calls, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const callback = () => undefined;
  const cancelled = [];
  const context = {};
  ref.on('value', callback, function(error) {
    cancelled.push({error, self: this});  // eslint-disable-line no-invalid-this
  }, context);
  const error = new Error('permission_denied');
  calls[0].cancelCallback.call(calls[0].context, error);
  assert.deepEqual(cancelled, [{error, self: context}], 'did not pass on the cancellation');

  configure(otherKey);
  database.ref('records/person').on('value', callback);
  ref.off('value', callback);

  assert.deepEqual(summarize(), [`on ${path}`, `on ${otherPath}`, `off ${otherPath}`]);
});

test('a context passed in place of the cancel callback is matched by off', () => {
  const {database, calls, configure, summarize} = createDatabase();
  const ref = database.ref('records/person');
  const callback = () => undefined;
  const context = {};
  ref.on('value', callback, context);
  assert.equal(calls[0].context, context);

  configure(undefined);
  ref.off('value', callback, context);

  assert.deepEqual(summarize(), [`on ${path}`, `off ${path}`]);
});
