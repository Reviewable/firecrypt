'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {wrapDatabase} = require('../dist/node/firecrypt');
const CryptoJS = require('crypto-js');

const key = Buffer.alloc(32, 0x42).toString('base64');
const siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
const encrypt = value =>
  '\x91S' + CryptoJS.enc.Base64url.stringify(siv.encrypt(value)) + '\x92';
const timestamp = {'.sv': 'timestamp'};

function createDatabase({error, encryption = 'aes-siv'} = {}) {
  const handles = [];
  const calls = [];

  class OnDisconnect {
    constructor(path) {
      this.path = path;
    }

    invoke(method, args) {
      const promise = error ? Promise.reject(error) : Promise.resolve();
      calls.push({receiver: this, method, path: this.path, args: Array.from(args), promise});
      const callback = args[method === 'set' || method === 'update' ? 1 : 0];
      if (callback) promise.then(() => callback(null), callback);
      return promise;
    }

    set() {
      return this.invoke('set', arguments);
    }

    update() {
      return this.invoke('update', arguments);
    }

    remove() {
      return this.invoke('remove', arguments);
    }

    cancel() {
      return this.invoke('cancel', arguments);
    }
  }

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

    onDisconnect() {
      const handle = new OnDisconnect(this.parts.join('/'));
      handles.push(handle);
      return handle;
    }
  }

  const database = wrapDatabase({app: {}, ref: (path = '') => new Reference().child(path)});
  database.configureFireCrypt({encryption, compression: 'none', key}, {
    rules: {
      records: {
        $record: {
          '.encrypt': {key: '#'},
          body: {'.encrypt': {value: '#'}},
          editedAt: {'.encrypt': {value: '#'}},
          state: {},
          patterned: {'.encrypt': {value: 'fixed|#'}},
          comments: {
            $comment: {
              '.encrypt': {key: '#'},
              body: {'.encrypt': {value: '#'}},
              state: {},
            },
          },
        },
      },
      settings: {body: {'.encrypt': {value: '#'}}},
    },
  });
  return {database, handles, calls};
}

for (const base of ['', 'records', 'records/person']) {
  const encryptedBase = base === 'records/person' ? 'records/' + encrypt('person') : base;

  test('onDisconnect.set at ' + (base || 'root') + ' dispatches fresh data', async () => {
    const {database, handles, calls} = createDatabase();
    const handle = database.ref(base).onDisconnect();
    const completed = [];
    const callback = error => completed.push(error);

    for (let i = 0; i < 2; i++) {
      const value = {body: 'secret ' + i, editedAt: timestamp, state: 'public', comments: null};
      const encrypted = {...value, body: encrypt(value.body)};
      const input = base === '' ? {records: {person: value}} :
        base === 'records' ? {person: value} : value;
      const expected = base === '' ? {records: {[encrypt('person')]: encrypted}} :
        base === 'records' ? {[encrypt('person')]: encrypted} : encrypted;
      const original = structuredClone(input);
      const result = i === 0 ? handle.set(input, callback) : handle.set(input);

      assert.equal(calls.length, i + 1, 'even the first call must reach Firebase immediately');
      assert.equal(calls[i].receiver, handles[0]);
      assert.equal(calls[i].path, encryptedBase);
      assert.equal(calls[i].method, 'set');
      assert.deepEqual(calls[i].args, i === 0 ? [expected, callback] : [expected]);
      assert.equal(result, calls[i].promise);
      await result;
      assert.deepEqual(input, original);
    }
    assert.deepEqual(completed, [null]);
    assert.equal(handles.length, 1);
  });

  test('onDisconnect.update at ' + (base || 'root') + ' encrypts paths and values', async () => {
    const {database, handles, calls} = createDatabase();
    const handle = database.ref(base).onDisconnect();
    const prefix = base === '' ? 'records/person/' : base === 'records' ? 'person/' : '';
    const encryptedPrefix = base === '' ? 'records/' + encrypt('person') + '/' :
      base === 'records' ? encrypt('person') + '/' : '';
    const completed = [];
    const callback = error => completed.push(error);

    for (let i = 0; i < 2; i++) {
      const input = {
        [prefix + 'body']: 'secret ' + i,
        [prefix + 'editedAt']: timestamp,
        [prefix + 'state']: 'public',
        [prefix + 'comments/one']: {body: 'comment ' + i, state: 'draft'},
        [prefix + 'comments/two']: null,
      };
      const original = structuredClone(input);
      const expected = {
        [encryptedPrefix + 'body']: encrypt('secret ' + i),
        [encryptedPrefix + 'editedAt']: timestamp,
        [encryptedPrefix + 'state']: 'public',
        [encryptedPrefix + 'comments/' + encrypt('one')]: {
          body: encrypt('comment ' + i), state: 'draft',
        },
        [encryptedPrefix + 'comments/' + encrypt('two')]: null,
      };
      const result = i === 0 ? handle.update(input, callback) : handle.update(input);

      assert.equal(calls.length, i + 1, 'each update must use its current arguments');
      assert.equal(calls[i].receiver, handles[0]);
      assert.equal(calls[i].path, encryptedBase);
      assert.equal(calls[i].method, 'update');
      assert.deepEqual(calls[i].args, i === 0 ? [expected, callback] : [expected]);
      assert.equal(result, calls[i].promise);
      await result;
      assert.deepEqual(input, original);
    }
    assert.deepEqual(completed, [null]);
    assert.equal(handles.length, 1);
  });

  for (const method of ['remove', 'cancel']) {
    test('onDisconnect.' + method + ' at ' + (base || 'root') + ' forwards each call', async () => {
      const {database, handles, calls} = createDatabase();
      const handle = database.ref(base).onDisconnect();
      const completed = [];
      const callback = error => completed.push(error);

      for (let i = 0; i < 2; i++) {
        const result = i === 0 ? handle[method](callback) : handle[method]();

        assert.equal(calls.length, i + 1);
        assert.equal(calls[i].receiver, handles[0]);
        assert.equal(calls[i].path, encryptedBase);
        assert.equal(calls[i].method, method);
        assert.deepEqual(calls[i].args, i === 0 ? [callback] : []);
        assert.equal(result, calls[i].promise);
        await result;
      }
      assert.deepEqual(completed, [null]);
    });
  }
}

for (const method of ['set', 'update', 'remove', 'cancel']) {
  test('onDisconnect.' + method + ' preserves rejected promises and error callbacks', async () => {
    const failure = new Error('offline test failure');
    const {database, calls} = createDatabase({error: failure});
    const handle = database.ref('records/person').onDisconnect();
    const completed = [];
    const callback = error => completed.push(error);
    const result = method === 'set' || method === 'update' ?
      handle[method]({body: 'secret'}, callback) : handle[method](callback);

    assert.equal(calls.length, 1);
    assert.equal(result, calls[0].promise);
    await assert.rejects(result, error => error === failure);
    assert.deepEqual(completed, [failure]);
  });
}

test('onDisconnect.set transforms scalar values using the logical reference path', async () => {
  const {database, calls} = createDatabase();
  await database.ref('records/person/body').onDisconnect().set('secret');

  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, 'records/' + encrypt('person') + '/body');
  assert.deepEqual(calls[0].args, [encrypt('secret')]);
});

test('onDisconnect encryption errors happen before scheduling a Firebase operation', () => {
  const {database, calls} = createDatabase();
  const handle = database.ref('records/person').onDisconnect();

  assert.throws(() => handle.set({patterned: 'invalid'}), {firecrypt: 'BAD_VALUE'});
  assert.deepEqual(calls, []);
});

test('onDisconnect rejects encrypted writes when the key is not ready', () => {
  const {database, calls} = createDatabase({encryption: 'notready'});
  const handle = database.ref('settings').onDisconnect();

  assert.throws(() => handle.update({body: 'secret'}), {firecrypt: 'NO_KEY'});
  assert.deepEqual(calls, []);
});

test('onDisconnect forwards plaintext writes when encryption is disabled', async () => {
  const {database, calls} = createDatabase({encryption: 'none'});
  const input = {body: 'secret', editedAt: timestamp};
  await database.ref('records/person').onDisconnect().set(input);

  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, 'records/person');
  assert.deepEqual(calls[0].args, [input]);
});
