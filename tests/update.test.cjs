'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {wrapDatabase} = require('../dist/node/firecrypt');
const CryptoJS = require('crypto-js');

// Synthetic AES-SIV key; these tests never instantiate or connect to a Firebase SDK.
const encryptionKey = Buffer.alloc(32, 0x42).toString('base64');
const siv = CryptoJS.SIV.create(CryptoJS.enc.Base64.parse(encryptionKey));
const encryptString = value =>
  '\x91S' + CryptoJS.enc.Base64url.stringify(siv.encrypt(value)) + '\x92';
const queueKey = 'owner|repo|123|user';
const encryptedQueueKey = [encryptString('owner'), encryptString('repo'), '123', 'user'].join('|');
const queuePath = 'queues/publishOnPush/' + queueKey;
const encryptedQueuePath = 'queues/publishOnPush/' + encryptedQueueKey;
const timestamp = {'.sv': 'timestamp'};

function createDatabase() {
  const writes = [];

  // Firebase's Path and pathChild ignore empty segments and keep child paths relative:
  // https://github.com/firebase/firebase-js-sdk/blob/main/packages/database/src/core/util/Path.ts
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

    update(values) {
      // Capture the exact receiver and payload supplied by the public FireCrypt wrapper.
      writes.push({path: this.parts.join('/'), values});
      return Promise.resolve();
    }
  }

  const database = wrapDatabase({
    app: {},
    ref: (path = '') => new Reference().child(path),
  });
  database.configureFireCrypt({encryption: 'aes-siv', compression: 'none', key: encryptionKey}, {
    rules: {
      queues: {
        publishOnPush: {
          $task: {
            '.encrypt': {key: '#|#|.|.'},
            writtenFingerprint: {},
            comments: {
              $comment: {
                '.encrypt': {key: '#'},
                body: {'.encrypt': {value: '#'}},
                author: {'.encrypt': {value: '#'}},
                editedAt: {'.encrypt': {value: '#'}},
                state: {},
                visible: {},
              },
            },
          },
        },
      },
      unencrypted: {},
    },
  });
  return {database, writes};
}

const pathFormats = {
  canonical: path => path,
  'leading slash': path => '/' + path,
  'multiple leading slashes': path => '///' + path,
  'redundant separators': path => path.replaceAll('/', '//'),
  'trailing slash': path => path + '/',
  'multiple trailing slashes': path => path + '///',
  'all separator forms': path => '//' + path.replaceAll('/', '///') + '//',
};

for (const base of ['', 'queues', 'queues/publishOnPush', queuePath]) {
  const baseDepth = base ? base.split('/').length : 0;
  const relativePath = path => path.split('/').slice(baseDepth).join('/');
  const encryptedBase = encryptedQueuePath.split('/').slice(0, baseDepth).join('/');

  for (const [formatName, format] of Object.entries(pathFormats)) {
    const location = base || 'root';
    test('update at ' + location + ' encrypts composite keys with ' + formatName, async () => {
      const {database, writes} = createDatabase();
      const values = {[format(relativePath(queuePath + '/writtenFingerprint'))]: 'fingerprint'};

      await database.ref(base).update(values);

      assert.deepEqual(writes, [{
        path: encryptedBase,
        values: {
          [format(relativePath(encryptedQueuePath + '/writtenFingerprint'))]: 'fingerprint',
        },
      }]);
    });

    test('update at ' + location + ' encrypts comment values with ' + formatName, async () => {
      const {database, writes} = createDatabase();
      const inputPath = suffix => format(relativePath(queuePath + '/comments/' + suffix));
      const outputPath = (comment, suffix = '') => format(relativePath(
        encryptedQueuePath + '/comments/' + encryptString(comment) + suffix));
      const values = {
        [inputPath('comment-1')]: {
          body: 'private comment',
          author: 'writer',
          editedAt: timestamp,
          state: 'published',
          visible: false,
        },
        [inputPath('comment-2')]: null,
        [inputPath('comment-3/body')]: null,
        [inputPath('comment-3/editedAt')]: timestamp,
        [inputPath('comment-4/body')]: 'direct secret',
        [inputPath('comment-4/state')]: 'draft',
      };
      const original = structuredClone(values);

      await database.ref(base).update(values);

      assert.deepEqual(writes, [{
        path: encryptedBase,
        values: {
          [outputPath('comment-1')]: {
            body: encryptString('private comment'),
            author: encryptString('writer'),
            editedAt: timestamp,
            state: 'published',
            visible: false,
          },
          [outputPath('comment-2')]: null,
          [outputPath('comment-3', '/body')]: null,
          [outputPath('comment-3', '/editedAt')]: timestamp,
          [outputPath('comment-4', '/body')]: encryptString('direct secret'),
          [outputPath('comment-4', '/state')]: 'draft',
        },
      }]);
      assert.deepEqual(values, original, 'update must not mutate the caller payload');
    });
  }
}

test('update preserves equivalent path spellings for Firebase overlap validation', async () => {
  const {database, writes} = createDatabase();
  const path = queuePath + '/writtenFingerprint';
  const encryptedPath = encryptedQueuePath + '/writtenFingerprint';

  // Firebase rejects these aliases as overlapping paths. Removing separators here would
  // silently overwrite one entry before Firebase's validateFirebaseMergePaths could run.
  await database.ref().update({[path]: 'first', ['/' + path]: 'second', [path + '/']: 'third'});

  assert.deepEqual(writes, [{
    path: '',
    values: {
      [encryptedPath]: 'first',
      ['/' + encryptedPath]: 'second',
      [encryptedPath + '/']: 'third',
    },
  }]);
});

test('a slash-only update path uses the current reference specification', async () => {
  const {database, writes} = createDatabase();
  await database.ref(queuePath + '/comments/comment-1').update({
    '///': {body: 'private comment', editedAt: timestamp, state: 'published'},
  });

  assert.deepEqual(writes, [{
    path: encryptedQueuePath + '/comments/' + encryptString('comment-1'),
    values: {
      '///': {body: encryptString('private comment'), editedAt: timestamp, state: 'published'},
    },
  }]);
});

test('update leaves paths outside the encryption specification unchanged', async () => {
  const {database, writes} = createDatabase();
  const values = {'//unencrypted///child/': {body: 'public', removed: null, editedAt: timestamp}};
  await database.ref().update(values);
  await database.ref('unencrypted').update({'/child/': values['//unencrypted///child/']});

  assert.deepEqual(writes, [
    {path: '', values},
    {path: 'unencrypted', values: {'/child/': values['//unencrypted///child/']}},
  ]);
});
