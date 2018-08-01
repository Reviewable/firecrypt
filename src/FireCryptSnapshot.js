import * as crypto from './crypto';
import FireCryptReference from './FireCryptReference';

export default class FireCryptSnapshot {
  constructor(snap) {
    this._ref = crypto.decryptRef(snap.ref);
    this._path = crypto.refToPath(this._ref);
    this._snap = snap;

    this._delegateSnapshot('exists');
    this._delegateSnapshot('toJSON');
    this._delegateSnapshot('hasChildren');
    this._delegateSnapshot('numChildren');
  }

  _delegateSnapshot(methodName) {
    this[methodName] = function() {
      return this._snap[methodName].apply(this._snap, arguments);
    };
  }

  get key() {
    return this._ref.key;
  }

  get ref() {
    return new FireCryptReference(this._ref.ref);
  }

  val() {
    return crypto.transformValue(this._path, this._snap.val(), crypto.decrypt);
  }

  child(childPath) {
    return new FireCryptSnapshot(this._snap.child(childPath));
  }

  forEach(action) {
    return this._snap.forEach(function(childSnap) {
      return action(new FireCryptSnapshot(childSnap));
    });
  }

  hasChild(childPath) {
    childPath = crypto.encryptPath(childPath.split('/'), crypto.specForPath(this._path)).join('/');
    return this._snap.hasChild(childPath);
  }

  exportVal() {
    return crypto.transformValue(this._path, this._snap.exportVal(), crypto.decrypt);
  }
}
