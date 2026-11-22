'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {setImmediate: nextTurn} = require('node:timers/promises');
const {getFireCryptCacheStats, wrapDatabase} = require('../dist/node/firecrypt');
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

function createDatabase(storedValue = null, attempts = 1, options = {}) {
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

    orderByKey() {return this;}
    orderByValue() {return this;}
    orderByChild() {return this;}

    equalTo(candidate, tieKey) {
      this.capture('equalTo', {value: candidate, key: tieKey});
      return this;
    }
  }

  const database = wrapDatabase({app: {}, ref: (path = '') => new Reference().child(path)});
  const configuration = {encryption: 'aes-siv', compression: 'none', key, ...options};
  const specification = {
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
  };
  database.configureFireCrypt(configuration, specification);
  return {configuration, database, specification, writes};
}

test('measured reads count stored values through decryption cache hits', async () => {
  const stored = [encrypt(false), encrypt(0), encrypt(''), null, {empty: null, value: 12}];
  const {database} = createDatabase(stored);
  const snap = await database.ref().once('value');
  assert.deepEqual(snap.val(), [false, 0, '', null, {empty: null, value: 12}]);
  const actual = snap.valWithSize();
  assert.deepEqual(actual.value, snap.val());
  assert.equal(actual.size.entries, 5);
  assert.equal(actual.size.containers, 2);
  assert.equal(actual.size.scalars, 4);
  assert.equal(actual.size.numbers, 1);
  assert.equal(actual.size.stringBytes,
    stored.slice(0, 3).reduce((sum, str) => sum + Math.ceil((16 + str.length) / 8) * 8, 0));
  assert.deepEqual(actual.size, snap.rawSize());
});

test('equivalent wrappers share caches across repeated configuration', async () => {
  const configuration = {
    compression: 'deflate', encryptionCacheSize: 6001, decryptionCacheSize: 6002
  };
  const value = 'compressible'.repeat(75);
  const first = createDatabase(null, 1, configuration);
  await first.database.ref('records/person/items').set([value]);
  const raw = first.writes.at(-1).value[0];
  assert.ok(raw.startsWith('\x91E'));
  const second = createDatabase(raw, 1, {...configuration, compressionOptions: {level: 9}});
  const stats = () => getFireCryptCacheStats().filter(item => item.encryption.capacity === 6001);
  await second.database.ref('records/person/items').set([value]);
  assert.equal(second.database.fireCryptStats.compression.attempts, 0);
  assert.equal(first.database.fireCryptStats.compression.attempts, 1);
  assert.equal(stats().length, 1);
  const snap = await second.database.ref().once('value');
  assert.equal(snap.valWithSize().value, value);
  assert.equal(snap.valWithSize().size.stringBytes, Math.ceil((16 + raw.length) / 8) * 8);
  assert.deepEqual(stats()[0].decryption, {
    count: 1, calculatedSize: raw.length + value.length, capacity: 6002,
    utilization: (raw.length + value.length) / 6002,
  });

  const before = stats();
  assert.deepEqual(first.database.fireCryptStats.caches, before[0]);
  assert.deepEqual(second.database.fireCryptStats.caches, before[0]);
  second.database.configureFireCrypt(second.configuration, second.specification);
  assert.deepEqual(second.database.fireCryptStats.caches, before[0]);
  assert.deepEqual(stats(), before);
  assert.equal(snap.val(), value);
});

test('configuration changes isolate keys, modes, compression, and limits', async () => {
  const configuration = {cacheSize: 6003};
  const first = createDatabase(encrypt('secret'), 1, configuration);
  const second = createDatabase(encrypt('secret'), 1, configuration);
  const snap = await first.database.ref().once('value');
  const otherSnap = await second.database.ref().once('value');
  assert.equal(snap.val(), 'secret');
  const stats = () => getFireCryptCacheStats().filter(item => item.decryption.capacity === 6003);
  const otherKey = Buffer.alloc(32, 89).toString('base64');
  assert.throws(() => second.database.configureFireCrypt(
    {...second.configuration, key: otherKey, keyCheckValue: first.database.encryptionKeyCheckValue},
    second.specification), {firecrypt: 'WRONG_KEY'});
  assert.equal(stats().length, 1);
  assert.equal(otherSnap.val(), 'secret');
  for (const changes of [
    {key: otherKey}, {encryption: 'notready'}, {compression: 'deflate'},
    {compression: 'deflate', compressionOptions: {level: 4}}, {encryptionCacheSize: 6004}
  ]) {
    second.database.configureFireCrypt({...second.configuration, ...changes}, second.specification);
    assert.equal(first.database.fireCryptStats.caches.decryption.count, 1);
    assert.equal(second.database.fireCryptStats.caches.decryption.count, 0);
    if (changes.key) assert.throws(() => otherSnap.val(), {firecrypt: 'WRONG_KEY'});
    if (changes.encryption) assert.throws(() => otherSnap.val(), {firecrypt: 'NO_KEY'});
  }
  assert.equal(snap.val(), 'secret');
});

test('compressible values do not warm encryption cache entries for path segments', async () => {
  const {database, writes} = createDatabase(null, 1, {compression: 'deflate'});
  const value = 'same'.repeat(100);
  await database.ref('records/person/items').set([value]);
  await database.ref('records').child(value).child('public').set('test');
  assert.ok(writes[0].value[0].startsWith('\x91E'));
  assert.equal(writes[1].path.split('/')[1], encrypt(value));
});

test('caches partial encryption by pattern across equivalent wrappers', async () => {
  const options = {encryptionCacheSize: 6011};
  const first = createDatabase(null, 1, options);
  const second = createDatabase(null, 1, options);
  const path = 'records/person/patterned';
  await first.database.ref(path).set(['left|right']);
  assert.deepEqual(first.writes.at(-1).value, [encrypt('left') + '|right']);
  // One encrypted path segment and one partial value.
  assert.equal(first.database.fireCryptStats.caches.encryption.count, 2);

  second.specification.rules.records.$.patterned = {$: {'.encrypt': {value: '.|#'}}};
  second.database.configureFireCrypt(second.configuration, second.specification);
  await second.database.ref(path).set(['left|right']);
  assert.deepEqual(second.writes.at(-1).value, ['left|' + encrypt('right')]);
  assert.equal(first.database.fireCryptStats.caches.encryption.count, 3);

  await first.database.ref(path).set(['left|right']);
  assert.deepEqual(first.writes.at(-1).value, [encrypt('left') + '|right']);
  assert.equal(second.database.fireCryptStats.caches.encryption.count, 3);
});

test('unreferenced wrappers do not retain shared cache pairs', {
  skip: typeof global.gc !== 'function'
}, async () => {
  const cachedPairExists = () => getFireCryptCacheStats().some(({encryption}) =>
    encryption.capacity === 6012);
  createDatabase(null, 1, {encryptionCacheSize: 6012});
  assert.equal(cachedPairExists(), true);
  for (let attempt = 0; attempt < 10; attempt++) {
    // deref() keeps its target alive until the end of this job.
    await nextTurn();
    global.gc();
    if (!cachedPairExists()) return;
  }
  assert.equal(cachedPairExists(), false);
});

test('equality query operands match compressed writes on cold and warm caches', async () => {
  const value = 'compressible'.repeat(25);
  const cases = [
    {
      write: (ref, content) => ref.child(content).set(content),
      query: ref => ref.orderByValue(),
      storedValue: write => write.value
    },
    {
      write: (ref, content) => ref.child(content).set({field: content}),
      query: ref => ref.orderByChild('field'),
      storedValue: write => write.value.field
    }
  ];
  for (const [index, {write, query, storedValue}] of cases.entries()) {
    // A distinct capacity gives each case an empty cache before either the query or write.
    const {database, specification, configuration, writes} = createDatabase(null, 1, {
      compression: 'deflate', encryptionCacheSize: 6100 + index
    });
    specification.rules.collection = {
      $: {'.encrypt': {key: '#', value: '#'}, field: {'.encrypt': {value: '#'}}}
    };
    database.configureFireCrypt(configuration, specification);
    const ref = database.ref('collection');
    query(ref).equalTo(value, value);
    assert.ok(writes[0].value.value.startsWith('\x91E'));
    assert.equal(writes[0].value.key, encrypt(value));
    await write(ref, value);
    query(ref).equalTo(value, value);
    assert.equal(writes[0].value.value, storedValue(writes[1]));
    assert.deepEqual(writes[2].value, writes[0].value);
    ref.orderByKey().equalTo(value);
    assert.equal(writes[3].value.value, encrypt(value));
  }
});

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
