import * as crypto from './crypto';

export default class FireCryptSnapshot {
  constructor(snap) {
    this._ref = crypto.decryptRef(snap.ref());
    this._path = crypto.refToPath(this._ref);
    this._snap = snap;

    this._delegateSnapshot('exists');
    this._delegateSnapshot('hasChildren');
    this._delegateSnapshot('numChildren');
    this._delegateSnapshot('getPriority');
  }

  _delegateSnapshot(methodName) {
    this[methodName] = function() {
      return this._snap[methodName].apply(this._snap, arguments);
    };
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

  key() {
    return this._ref.key();
  }
  
  name() {
    return this._ref.name();
  }
  
  ref() {
    return this._ref;
  }
  
  exportVal() {
    return crypto.transformValue(this._path, this._snap.exportVal(), crypto.decrypt);
  }
}
