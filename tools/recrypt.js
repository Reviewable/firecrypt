#!/usr/bin/env node
'use strict';

const _ = require('lodash');
const admin = require('firebase-admin');
const childProcess = require('child_process');
const commandLineArgs = require('command-line-args');
const fs = require('fs');
const getUsage = require('command-line-usage');
const HttpsAgent = require('agentkeepalive').HttpsAgent;
const ms = require('ms');
const NodeFire = require('nodefire').default;
const os = require('os');
const joinPath = require('path').join;
const streamToPromise = require('stream-to-promise');

NodeFire.setCacheSize(0);

const commandLineOptions = [
  {name: 'firebase', alias: 'f',
    typeLabel: '{underline database}',
    description: 'The unique id of the target realtime database (required).'},
  {name: 'auth', alias: 'a',
    typeLabel: '{underline file}',
    description: 'A JSON file with credentials for the database (required).'},
  {name: 'spec', alias: 's',
    typeLabel: '{underline file}',
    description: 'The firecrypt rules JSON file (required).'},
  {name: 'oldKey', alias: 'o',
    typeLabel: '{underline base64key}',
    description: 'The old encryption key to be replaced.'},
  {name: 'newKey', alias: 'n',
    typeLabel: '{underline base64key}',
    description: 'The new encryption key to use.'},
  {name: 'cpus', alias: 'c', defaultValue: os.cpus().length,
    typeLabel: '{underline number}',
    description: 'The number of CPUs to use (defaults to all available).'},
  {name: 'help', alias: 'h',
    description: 'Display these usage instructions.'},
  {name: 'log', alias: 'l',
    typeLabel: '{underline file}',
    description: 'Stream logging messages to a file for debugging.'}
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

const MAX_KEY_REQUESTS_IN_FLIGHT = 5;
const SMALL_COMMANDS_THRESHOLD = 1000, WILDCARD_KEYS_CHUNK_SIZE = 250;
const MAX_UPDATES_SIZE = 500, MAX_UPDATES_IN_FLIGHT = 10, MAX_UPDATE_TRIES = 5;
const MILLION = 1048576;


const args = commandLineArgs(commandLineOptions);
if ('help' in args) {
  console.log(getUsage(usageSpec));
  process.exit(0);
}
try {
  for (const property of ['firebase', 'auth', 'spec']) {
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

_.assign(exports, {traverse, queueUpdates});

const logWriteStream = args.log ? fs.createWriteStream(args.log) : null;
const db = new NodeFire(initializeFirebase(args.firebase, args.auth));

const agent = new HttpsAgent({
  keepAliveMsecs: ms('1s'), freeSocketTimeout: ms('15s'), timeout: ms('30s'),
  maxSockets: MAX_KEY_REQUESTS_IN_FLIGHT, maxFreeSockets: 1
});

const spec = expandSpecification(JSON.parse(fs.readFileSync(args.spec))).rules;
// console.log(JSON.stringify(spec, null, 2));

const pace = require('pace')(1);
const workers = [];


class UpdateQueue {
  constructor() {
    this._updatesInFlight = 0;
    this._queue = [];
    this._batch = {};
    this._batchSize = 0;
    this._stats = {enqueued: 0, sent: 0, delayed: 0, retries: 0};
  }

  add(updates) {
    const size = this._estimateSize(updates);
    if (size >= MAX_UPDATES_SIZE) {
      // send it out by itself
      log('sendUpdates', size);
      this._enqueue(updates);
      return;
    } else if (this._batchSize + size > MAX_UPDATES_SIZE) {
      this._flush();
    }
    log('queueUpdates', size);
    _.assign(this._batch, updates);
    this._batchSize += size;
  }

  drain() {
    if (!this._drainPromise) {
      this._drainPromise = new Promise(resolve => {this._resolveDrainPromise = resolve;});
    }
    this._flush();
    return this._drainPromise;
  }

  _refresh() {
    while (this._updatesInFlight < MAX_UPDATES_IN_FLIGHT && this._queue.length) {
      this._updatesInFlight += 1;
      this._send(this._queue.shift()).catch(handleFatalError);
    }
    if (this._resolveDrainPromise && !this._updatesInFlight && !this._queue.length) {
      this._resolveDrainPromise();
    }
  }

  async _send(updates) {
    // log(require('util').inspect(updates, false, 0));
    for (let tries = 0; tries < MAX_UPDATE_TRIES; tries++) {
      try {
        await db.update(updates);
      } catch (e) {
        log('Retrying update due to', e);
        this._stats.retries += 1;
        continue;
      }
      this._stats.sent += 1;
      this._updatesInFlight -= 1;
      pace.op();
      this._refresh();
      return;
    }
    log('Update failed', MAX_UPDATE_TRIES, 'times, aborting');
    log(updates);
    console.log('\n\nUpdate failed', MAX_UPDATE_TRIES, 'times, aborting');
    process.exit(1);
  }

  _flush() {
    if (!_.isEmpty(this._batch)) {
      log('flushUpdates', this._batchSize);
      this._enqueue(this._batch);
      this._batch = {};
      this._batchSize = 0;
    }
    this._refresh();
  }

  _enqueue(updates) {
    pace.total += 1;
    this._queue.push(updates);
    this._refresh();
    if (this._queue.length) this._stats.delayed += 1;
    if (++this._stats.enqueued % 10 === 0) {
      log('updateStats', _.map(this._stats, (value, key) => `${key}: ${value}`).join(', '));
    }
  }

  _estimateSize(object) {
    if (!_.isObject(object)) return 0;
    return _.reduce(object, (size, value) => size + this._estimateSize(value), _.size(object));
  }
}

const updateQueue = new UpdateQueue();

function queueUpdates(updates) {
  updateQueue.add(updates);
}


class CommandQueue {
  constructor() {
    this._bigCommands = [];
    this._smallCommands = [];
    this._numPendingCalls = 0;
    this._numAdds = 0;
  }

  add() {
    pace.total += 1;
    const command = {cmd: 'call', fn: arguments[0], args: _.slice(arguments, 1)};
    switch (command.fn) {
      case 'traverseWildcard':
      case 'traverseSpec':
        this._bigCommands.push(command);
        break;
      case 'traverseSmall':
      case 'transformSmall':
        this._smallCommands.push(command);
        break;
      default:
        throw new Error('Unknown command: ' + command.fn);
    }
    this.refresh();
    if (++this._numAdds % 1000 === 0) {
      const mem = process.memoryUsage();
      log(
        `commandStats big: ${this._bigCommands.length}, small: ${this._smallCommands.length},`,
        `rss: ${_.round(mem.rss / MILLION)}, heap: ${_.round(mem.heapUsed / MILLION)}`
      );
    }
  }

  drain() {
    if (!this._completePromise) {
      this._completePromise = new Promise(resolve => {this._resolveCompletePromise = resolve;});
    }
    return this._completePromise;
  }

  refresh() {
    let worker;
    while ((this._smallCommands.length || this._bigCommands.length) &&
           (worker = _.find(workers, 'ready'))) {
      const numRunningSmallCommands = _(workers).reject('ready').filter('small').size();
      const small =
        this._smallCommands.length && (
          this._smallCommands.length > SMALL_COMMANDS_THRESHOLD ||
          numRunningSmallCommands < args.cpus / 2 ||
          !this._bigCommands.length);
      const command = (small ? this._smallCommands : this._bigCommands).pop();
      worker.execute(command, small);
    }
    if (this._resolveCompletePromise && !this._numPendingCalls && !this._bigCommands.length &&
        !this._smallCommands.length && _.every(workers, 'ready')) {
      this._resolveCompletePromise();
    }
  }

  waitFor(callResult) {
    if (callResult) {
      this._numPendingCalls++;
      callResult.then(() => {
        this._numPendingCalls--;
        this.refresh();
      }, handleFatalError);
    }
  }
}

const commandQueue = new CommandQueue();


class Worker {
  constructor(index) {
    this.index = index;
    const initOptions = {cmd: 'init', spec};
    if (args.newKey) initOptions.newKey = args.newKey;
    if (args.oldKey) initOptions.oldKey = args.oldKey;
    this.ready = true;
    this.child = childProcess.fork(joinPath(__dirname, 'recrypt_worker.js'));
    this.child.on('message', msg => this.handleMessage(msg));
    this.child.on('exit', ev => this.handleExit(ev));
    this.child.on('error', ev => this.handleError(ev));
    this.child.send(initOptions);
  }

  handleMessage(msg) {
    switch (msg.cmd) {
      case 'ready':
        pace.op();
        this.ready = true;
        commandQueue.refresh();
        break;
      case 'call':
        commandQueue.waitFor(exports[msg.fn].apply(null, msg.args));
        break;
      case 'stats':
        log('workerStats', this.index, _.map(msg.stats, (stat, key) => {
          const hitRate = _.round(stat.hits / Math.max(stat.hits + stat.misses, 1) * 100, 1);
          return `${key}: ${hitRate}% of ${stat.hits + stat.misses}`;
        }).join(', '));
        break;
      default:
        throw new Error('Invalid message from worker: ' + msg.cmd);
    }
  }

  handleExit(ev) {
    console.log('\n\nChild worker exited prematurely, aborting');
    process.exit(1);
  }

  handleError(ev) {
    console.log('\n\nChild worker error:', ev.err);
    process.exit(1);
  }

  execute(command, small) {
    this.ready = false;
    this.small = small;
    log(command.fn, command.args[1]);
    this.child.send(command);
  }
}


async function run() {
  _.times(args.cpus, i => {workers.push(new Worker(i + 1));});
  await traverse('', '', '');
  await commandQueue.drain();
  await updateQueue.drain();
  pace.op();
  if (logWriteStream) {
    const logPromise = streamToPromise(logWriteStream);
    logWriteStream.end();
    await logPromise;
  }
}

run().then(() => {
  process.exit(0);
}, handleFatalError);


function expandSpecification(def, path) {
  const flags = def['.encrypt'] || {};
  _.forEach(_.keys(def), key => {
    if (key === '.encrypt') {
      const badSubKeys = _.reject(
        _.keys(def[key]), subKey => _.includes(['key', 'value', 'few', 'big', 'children'], subKey));
      if (badSubKeys.length) throw new Error('Illegal .encrypt subkeys: ' + badSubKeys.join(', '));
    } else {
      if (key.charAt(0) === '.') throw new Error('Unknown directive at ' + path + ': ' + key);
      // eslint-disable-next-line no-control-regex
      if (/[\x00-\x1f\x7f\x91\x92.#[\]/]/.test(key) || /[$]/.test(key.slice(1))) {
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

async function traverse(specPath, oldPath, newPath, copy) {
  const def = defForPath(specPath);
  const oldChild = oldPath ? db.child(oldPath) : db;
  try {
    const flags = def['.encrypt'] || {};
    if (copy && !flags.big) {
      pace.total += 1;
      const leaf = await oldChild.get();
      pace.op();
      if (leaf) commandQueue.add('transformSmall', specPath, oldPath, newPath, leaf);
    } else if (def.$) {
      if (flags.big) {
        const keys = await requestKeys(oldChild);
        _.forEach(_.chunk(keys, WILDCARD_KEYS_CHUNK_SIZE), keysChunk => {
          commandQueue.add('traverseWildcard', specPath, oldPath, newPath, copy, keysChunk);
        });
      } else {
        // !flags.big && !copy
        pace.total += 1;
        const leaf = await oldChild.get();
        pace.op();
        if (leaf) commandQueue.add('traverseSmall', specPath, oldPath, newPath, leaf);
      }
    } else {
      commandQueue.add('traverseSpec', specPath, oldPath, newPath, copy);
    }
  } catch (e) {
    e.specPath = specPath;
    e.oldPath = oldPath;
    e.newPath = newPath;
    throw e;
  }
}


const childrenKeysOptions = {maxTries: 3, retryInterval: ms('1s'), agent};

async function requestKeys(ref) {
  pace.total += 1;
  try {
    log('requestKeys', ref.path);
    return await ref.childrenKeys(childrenKeysOptions);
  } catch (e) {
    log('requestKeys', ref.path, e);
    throw e;
  } finally {
    pace.op();
  }
}

function defForPath(path) {
  if (!path) return spec;
  return _.reduce(path.split('/'), (def, segment) => def[segment], spec);
}

function initializeFirebase(firebaseId, credentialsFilename) {
  const firebaseConfig = {
    databaseURL: `https://${firebaseId}.firebaseio.com`
  };

  let fileIssue;
  if (!fs.existsSync(credentialsFilename)) {
    fileIssue = 'does not exist';
  } else if (fs.lstatSync(credentialsFilename).isDirectory()) {
    fileIssue = 'is a directory, not a file';
  }

  if (fileIssue) {
    throw new Error(
      `Unable to authenticate the Firebase Admin SDK. The path to a Firebase service account key \
JSON file specified via the REVIEWABLE_FIREBASE_CREDENTIALS_FILE environment variable \
(${credentialsFilename}) ${fileIssue}. Navigate to \
https://console.firebase.google.com/u/0/project/_/settings/serviceaccounts/adminsdk to generate \
that file and make sure the specified path is correct.`
    );
  }

  const serviceAccount = JSON.parse(fs.readFileSync(credentialsFilename));
  firebaseConfig.credential = admin.credential.cert(serviceAccount);
  admin.initializeApp(firebaseConfig);
  return admin.database().ref();
}

function log() {
  if (logWriteStream) {
    logWriteStream.write(_(arguments).toArray().invokeMap('toString').join(' ') + '\n');
  }
}

function handleFatalError(e) {
  log('fatal error', e.stack);
  console.log('\n');
  console.log(e.stack);
  process.exit(1);
}
