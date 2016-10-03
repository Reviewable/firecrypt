#!/usr/bin/env node
'use strict';

const _ = require('lodash');
const childProcess = require('child_process');
const co = require('co');
const commandLineArgs = require('command-line-args');
const fs = require('fs');
const getUsage = require('command-line-usage');
const HttpsAgent = require('agentkeepalive').HttpsAgent;
const ms = require('ms');
const NodeFire = require('nodefire');
const os = require('os');
const request = require('request');
const streamToPromise = require('stream-to-promise');

NodeFire.setCacheSize(0);

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
  {name: 'cpus', alias: 'c', defaultValue: os.cpus().length,
   typeLabel: '[underline]{number}',
   description: 'The number of CPUs to use (defaults to all available).'},
  {name: 'help', alias: 'h',
   description: 'Display these usage instructions.'},
  {name: 'log', alias: 'l',
   typeLabel: '[underline]{file}',
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

_.extend(exports, {traverse, queueUpdates});

const logWriteStream = args.log ? fs.createWriteStream(args.log) : null;
const firebaseUrl = 'https://' + args.firebase + '.firebaseio.com';
const firebaseAuth = args.auth;
const db = new NodeFire(firebaseUrl);

const agent = new HttpsAgent({
  keepAliveMsecs: ms('1s'), keepAliveTimeout: ms('15s'), timeout: ms('30s'),
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
    _.extend(this._batch, updates);
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
      co(this._send(this._queue.shift())).catch(handleFatalError);
    }
    if (this._resolveDrainPromise && !this._updatesInFlight && !this._queue.length) {
      this._resolveDrainPromise();
    }
  }

  *_send(updates) {
    for (let tries = 0; tries < MAX_UPDATE_TRIES; tries++) {
      try {
        yield db.update(updates);
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
      let mem = process.memoryUsage();
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
      const commands =
        this._smallCommands.length && (
          this._smallCommands.length > SMALL_COMMANDS_THRESHOLD ||
          numRunningSmallCommands < args.cpus / 2 ||
          !this._bigCommands.length) ? this._smallCommands : this._bigCommands;
      const command = _.pullAt(commands, _.random(commands.length - 1))[0];
      worker.execute(command, commands === this._smallCommands);
    }
    if (this._resolveCompletePromise && !this._numPendingCalls && !this._bigCommands.length &&
        !this._smallCommands.length && _.every(workers, 'ready')) {
      this._resolveCompletePromise();
    }
  }

  waitFor(callResult) {
    if (callResult && typeof callResult.next === 'function' &&
        typeof callResult.throw === 'function') {
      this._numPendingCalls++;
      co(callResult).then(() => {
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
    this.child = childProcess.fork('recrypt_worker.js');
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
        log('workerStats', _.map(msg.stats, (stat, key) => {
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


co(function*() {
  yield db.auth(firebaseAuth);
  _.times(args.cpus, i => {workers.push(new Worker(i + 1));});
  yield traverse('', '', '');
  yield commandQueue.drain();
  yield updateQueue.drain();
  pace.op();
  if (logWriteStream) {
    const logPromise = streamToPromise(logWriteStream);
    logWriteStream.end();
    yield logPromise;
  }
}).then(() => {
  process.exit(0);
}, handleFatalError);


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

function *traverse(specPath, oldPath, newPath, copy) {
  const def = defForPath(specPath);
  try {
    const flags = def['.encrypt'] || {};
    if (copy && !flags.big) {
      pace.total += 1;
      const leaf = yield db.child(oldPath).get();
      pace.op();
      if (leaf) commandQueue.add('transformSmall', specPath, oldPath, newPath, leaf);
    } else {
      if (def.$) {
        if (flags.big) {
          const keys = yield requestKeys(oldPath);
          _.each(_.chunk(keys, WILDCARD_KEYS_CHUNK_SIZE), keysChunk => {
            commandQueue.add('traverseWildcard', specPath, oldPath, newPath, copy, keysChunk);
          });
        } else {
          // !flags.big && !copy
          pace.total += 1;
          const leaf = yield db.child(oldPath).get();
          pace.op();
          if (leaf) commandQueue.add('traverseSmall', specPath, oldPath, newPath, leaf);
        }
      } else {
        commandQueue.add('traverseSpec', specPath, oldPath, newPath, copy);
      }
    }
  } catch (e) {
    e.specPath = specPath;
    e.oldPath = oldPath;
    e.newPath = newPath;
    throw e;
  }
}


function requestKeys(path) {
  pace.total += 1;
  return new Promise((resolve, reject) => {
    let tries = 0;
    const uriPath =
      '/' + _(path.split('/')).compact().map(part => encodeURIComponent(part)).join('/');
    const req = () => {
      log('requestKeys', path);
      request({
        uri: firebaseUrl + uriPath + '.json', qs: {auth: firebaseAuth, shallow: true}, agent: agent
      }, (error, response, data) => {
        if (!error) {
          try {
            const regex = /"(.*?)"/g, keys = [];
            let match;
            // jshint boss:true
            while (match = regex.exec(data)) keys.push(match[1]);  // don't unescape keys!
            // jshint boss:false
            pace.op();
            resolve(keys);
          } catch (e) {
            error = e;
          }
        }
        if (error) {
          log('requestKeys', path, error);
          if (++tries <= 3) req(); else {pace.op(); reject(error);}
        }
      });
    };
    req();
  });
}

function defForPath(path) {
  if (!path) return spec;
  return _.reduce(path.split('/'), (def, segment) => def[segment], spec);
}

function log() {
  if (logWriteStream) {
    logWriteStream.write(_(arguments).toArray().invokeMap('toString').join(' ') + '\n');
  }
}

function handleFatalError(e) {
  console.log('\n');
  console.log(e.stack);
  process.exit(1);
}
