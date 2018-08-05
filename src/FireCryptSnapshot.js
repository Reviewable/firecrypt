import * as crypto from './crypto';
import FireCryptReference from './FireCryptReference';

export default class FireCryptSnapshot {
  constructor(snap) {
    this._ref = crypto.decryptRef(snap.ref);
    this._path = crypto.refToPath(this._ref);
    this._snap = snap;
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

  exists() {
    return this._snap.exists.apply(this._snap, arguments)
  }

  hasChild(childPath) {
    childPath = crypto.encryptPath(childPath.split('/'), crypto.specForPath(this._path)).join('/');
    return this._snap.hasChild(childPath);
  }

  hasChildren() {
    return this._snap.hasChildren.apply(this._snap, arguments)
  }

  numChildren() {
    return this._snap.numChildren.apply(this._snap, arguments)
  }

  toJSON() {
    const json = this._snap.toJSON.apply(this._snap, arguments);
    return crypto.transformValue(this._path, json, crypto.decrypt);
  }
}
