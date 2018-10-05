import FireCryptReference from './FireCryptReference';

export default class FireCryptSnapshot {
  constructor(snap, crypto) {
    this._ref = crypto.decryptRef(snap.ref);
    this._path = crypto.refToPath(this._ref);
    this._snap = snap;
    this._crypto = crypto;
  }

  get key() {
    return this._ref.key;
  }

  get ref() {
    return new FireCryptReference(this._ref.ref, this._crypto);
  }

  val() {
    return this._crypto.transformValue(this._path, this._snap.val(), 'decrypt');
  }

  child(childPath) {
    return new FireCryptSnapshot(this._snap.child(childPath), this._crypto);
  }

  forEach(action) {
    return this._snap.forEach((childSnap) => {
      return action(new FireCryptSnapshot(childSnap), this._crypto);
    });
  }

  exists() {
    return this._snap.exists.apply(this._snap, arguments);
  }

  hasChild(childPath) {
    childPath = this._crypto.encryptPath(
      childPath.split('/'), this._crypto.specForPath(this._path)).join('/');
    return this._snap.hasChild(childPath);
  }

  hasChildren() {
    return this._snap.hasChildren.apply(this._snap, arguments);
  }

  numChildren() {
    return this._snap.numChildren.apply(this._snap, arguments);
  }

  toJSON() {
    const json = this._snap.toJSON.apply(this._snap, arguments);
    return this._crypto.transformValue(this._path, json, 'decrypt');
  }
}
