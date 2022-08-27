import FireCryptReference from './FireCryptReference';

export default class FireCryptSnapshot {
  constructor(snap, firecrypt) {
    this._ref = firecrypt._crypto.decryptRef(snap.ref);
    this._path = firecrypt._crypto.refToPath(this._ref);
    this._snap = snap;
    this._firecrypt = firecrypt;
  }

  get key() {
    return this._ref.key;
  }

  get ref() {
    return new FireCryptReference(this._ref.ref, this._firecrypt);
  }

  val() {
    return this._firecrypt._crypto.transformValue(this._path, this._snap.val(), 'decrypt');
  }

  child(childPath) {
    return new FireCryptSnapshot(this._snap.child(childPath), this._firecrypt);
  }

  forEach(action) {
    return this._snap.forEach((childSnap) => {
      return action(new FireCryptSnapshot(childSnap), this._firecrypt);
    });
  }

  exists() {
    return this._snap.exists.apply(this._snap, arguments);
  }

  hasChild(childPath) {
    childPath = this._firecrypt._crypto.encryptPath(
      childPath.split('/'), this._firecrypt._crypto.specForPath(this._path)).join('/');
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
    return this._firecrypt._crypto.transformValue(this._path, json, 'decrypt');
  }
}
