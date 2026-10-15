'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {wrapDatabase} = require('../dist/node/firecrypt');
const CryptoJS = require('crypto-js');

const key = Buffer.alloc(32, 0x42).toString('base64');
const siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
const encrypt = value =>
  '\x91S' + CryptoJS.enc.Base64url.stringify(siv.encrypt(value)) + '\x92';

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

    on(eventType, callback) {
      calls.push({method: 'on', path: this.parts.join('/'), eventType, callback});
      return callback;
    }

    off(eventType, callback) {
      calls.push({method: 'off', path: this.parts.join('/'), eventType, callback});
    }
  }

  const database = wrapDatabase({app: {}, ref: (path = '') => new Reference().child(path)});
  const configure = encryption => database.configureFireCrypt(
    {encryption, compression: 'none', key: encryption === 'aes-siv' ? key : undefined},
    {rules: {records: {$record: {'.encrypt': {key: '#'}}}}}
  );
  configure('aes-siv');
  return {database, calls, configure};
}

test('off on the reference that added a listener works after the key is released', () => {
  const {database, calls, configure} = createDatabase();
  const ref = database.ref('records/person');
  const callback = () => undefined;
  ref.on('value', callback);

  configure('notready');
  assert.throws(() => database.ref('records/person').off('value', callback), {firecrypt: 'NO_KEY'});
  ref.off('value', callback);

  const encryptedPath = 'records/' + encrypt('person');
  assert.deepEqual(calls.map(({method, path}) => ({method, path})), [
    {method: 'on', path: encryptedPath},
    {method: 'off', path: encryptedPath}
  ]);
  assert.equal(calls[1].callback, calls[0].callback, 'off must remove the wrapped callback');
});

test('off on a fresh reference still encrypts the path', () => {
  const {database, calls} = createDatabase();
  const callback = () => undefined;
  database.ref('records/person').on('value', callback);
  database.ref('records/person').off('value', callback);

  const encryptedPath = 'records/' + encrypt('person');
  assert.deepEqual(calls.map(({path}) => path), [encryptedPath, encryptedPath]);
  assert.equal(calls[1].callback, calls[0].callback);
});
