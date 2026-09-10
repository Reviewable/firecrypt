'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {wrapDatabase} = require('../dist/node/firecrypt');
const CryptoJS = require('crypto-js');

const key = Buffer.alloc(32, 0x42).toString('base64');
const siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(key));
const timestamp = {'.sv': 'timestamp'};

function encrypt(value) {
  if (value === null || typeof value === 'object') return value;
  const type = typeof value;
  const text = type === 'boolean' ? (value ? 't' : 'f') : String(value);
  return '\x91' + type[0].toUpperCase() +
    CryptoJS.enc.Base64url.stringify(siv.encrypt(text)) + '\x92';
}

function createDatabase(storedValue = null, attempts = 1) {
  const writes = [];

  class Reference {
    constructor(parts = []) {this.parts = parts;}

    get root() {return new Reference();}

    get ref() {return this;}

    child(path) {return new Reference([...this.parts, ...path.split('/').filter(Boolean)]);}

    isEqual(other) {return this.toString() === other.toString();}

    toString() {
      return 'https://firecrypt.test/' + this.parts.map(encodeURIComponent).join('/');
    }

    snapshot(value) {return {ref: this, val: () => value, toJSON: () => value};}

    capture(method, value) {
      writes.push({method, path: this.parts.join('/'), value: structuredClone(value)});
    }

    set(value) {
      this.capture('set', value);
      return Promise.resolve();
    }

    update(value) {
      this.capture('update', value);
      return Promise.resolve();
    }

    transaction(compute) {
      let value;
      for (let i = 0; i < attempts; i++) {
        value = compute(storedValue);
        this.capture('transaction', value);
      }
      return Promise.resolve({committed: true, snapshot: this.snapshot(value)});
    }

    once() {return Promise.resolve(this.snapshot(storedValue));}
  }

  const database = wrapDatabase({app: {}, ref: (path = '') => new Reference().child(path)});
  database.configureFireCrypt({encryption: 'aes-siv', compression: 'none', key}, {
    rules: {
      records: {
        $record: {
          '.encrypt': {key: '#'},
          items: {$item: {'.encrypt': {value: '#'}}},
          matrix: {$row: {$item: {'.encrypt': {value: '#'}}}},
          comments: {
            $comment: {
              body: {'.encrypt': {value: '#'}},
              labels: {$label: {'.encrypt': {value: '#'}}},
              visible: {},
            },
          },
          patterned: {$item: {'.encrypt': {value: '#|.'}}},
          public: {},
        },
      },
    },
  });
  return {database, writes};
}

function values() {
  return {
    items: ['secret', 42, true, false, 0, null, timestamp],
    matrix: [['nested', null], ['another']],
    comments: [{body: 'private', labels: ['label'], visible: false}],
    public: ['public', null, timestamp],
  };
}

function encryptedValues() {
  return {
    items: ['secret', 42, true, false, 0, null, timestamp].map(encrypt),
    matrix: [[encrypt('nested'), null], [encrypt('another')]],
    comments: [{body: encrypt('private'), labels: [encrypt('label')], visible: false}],
    public: ['public', null, timestamp],
  };
}

for (const base of ['', 'records', 'records/person']) {
  for (const method of ['set', 'update', 'transaction']) {
    test(method + ' at ' + (base || 'root') + ' preserves reusable nested arrays', async () => {
      const {database, writes} = createDatabase();
      const input = base === '' ? {records: {person: values()}} :
        base === 'records' ? {person: values()} : values();
      const original = structuredClone(input);
      const expected = base === '' ? {records: {[encrypt('person')]: encryptedValues()}} :
        base === 'records' ? {[encrypt('person')]: encryptedValues()} : encryptedValues();
      const expectedPath = base === 'records/person' ? 'records/' + encrypt('person') : base;

      for (let i = 0; i < 2; i++) {
        if (method === 'transaction') {
          const result = await database.ref(base).transaction(() => input);
          assert.deepEqual(input, original, 'transaction must not mutate its return value');
          assert.deepEqual(result.snapshot.val(), original);
        } else {
          await database.ref(base)[method](input);
        }
        assert.deepEqual(writes[i], {method, path: expectedPath, value: expected});
        assert.deepEqual(input, original, 'caller arrays must remain plaintext');
      }
    });
  }
}

test('a frozen array can be encrypted directly by set', async () => {
  const {database, writes} = createDatabase();
  const input = Object.freeze(['secret', null, Object.freeze({'.sv': 'timestamp'})]);

  await database.ref('records/person/items').set(input);

  assert.deepEqual(writes[0].value, [encrypt('secret'), null, timestamp]);
  assert.deepEqual(input, ['secret', null, timestamp]);
});

test('one array shared by two update paths is encrypted only once for each path', async () => {
  const {database, writes} = createDatabase();
  const input = ['secret', null];

  await database.ref('records').update({'alice/items': input, 'bob/items': input});

  assert.deepEqual(writes[0].value, {
    [encrypt('alice') + '/items']: [encrypt('secret'), null],
    [encrypt('bob') + '/items']: [encrypt('secret'), null],
  });
  assert.deepEqual(input, ['secret', null]);
});

test('failed encryption leaves partially traversed arrays unchanged', () => {
  const {database, writes} = createDatabase();
  const input = ['secret|suffix', 'invalid'];

  assert.throws(
    () => database.ref('records/person/patterned').set(input),
    {firecrypt: 'BAD_VALUE'}
  );

  assert.deepEqual(input, ['secret|suffix', 'invalid']);
  assert.deepEqual(writes, []);
});

test('snapshot reads preserve backing arrays and return independent arrays', async () => {
  const stored = [encrypt('secret'), [encrypt('nested')], null];
  const original = structuredClone(stored);
  const {database} = createDatabase(stored);
  const snapshot = await database.ref('records/person/items').once('value');
  const expected = ['secret', ['nested'], null];
  const value = snapshot.val();

  assert.deepEqual(value, expected);
  assert.deepEqual(stored, original);
  value[0] = 'changed';
  value[1][0] = 'also changed';
  assert.deepEqual(snapshot.val(), expected);
  assert.deepEqual(snapshot.toJSON(), expected);
  assert.deepEqual(stored, original);
});

test('transaction retries do not retain mutations from an earlier attempt', async () => {
  const stored = [encrypt('secret')];
  const {database, writes} = createDatabase(stored, 2);
  const seen = [];
  const result = await database.ref('records/person/items').transaction(value => {
    seen.push(structuredClone(value));
    value.push('added');
    return value;
  });

  assert.deepEqual(seen, [['secret'], ['secret']]);
  assert.deepEqual(writes.map(write => write.value), [
    [encrypt('secret'), encrypt('added')],
    [encrypt('secret'), encrypt('added')],
  ]);
  assert.deepEqual(stored, [encrypt('secret')]);
  assert.deepEqual(result.snapshot.val(), ['secret', 'added']);
});

test('sparse array writes preserve holes instead of creating undefined elements', async () => {
  const {database, writes} = createDatabase();
  const input = new Array(4);
  input[1] = 'secret';
  Object.freeze(input);
  const expected = new Array(4);
  expected[1] = encrypt('secret');

  await database.ref('records/person/items').set(input);

  assert.deepEqual(writes[0].value, expected);
  assert.deepEqual(Object.keys(input), ['1']);
  assert.equal(input[1], 'secret');
});

test('sparse snapshot arrays preserve holes without mutating the backing array', async () => {
  const stored = new Array(4);
  stored[1] = encrypt('secret');
  const {database} = createDatabase(stored);
  const expected = new Array(4);
  expected[1] = 'secret';
  const snapshot = await database.ref('records/person/items').once('value');

  assert.deepEqual(snapshot.val(), expected);
  assert.deepEqual(snapshot.toJSON(), expected);
  assert.deepEqual(Object.keys(stored), ['1']);
  assert.equal(stored[1], encrypt('secret'));
});
