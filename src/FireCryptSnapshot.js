import * as utils from './utils';
import FireCryptReference from './FireCryptReference';

export default class FireCryptSnapshot {
  constructor(snap) {
    this._ref = utils.decryptRef(snap.ref);
    this._path = utils.refToPath(this._ref);
    this._snap = snap;

    this._delegateSnapshot('exists');
    this._delegateSnapshot('toJSON');
    this._delegateSnapshot('hasChildren');
    this._delegateSnapshot('numChildren');
    this._delegateSnapshot('getPriority');
  }

  _delegateSnapshot(methodName) {
    this[methodName] = function() {
      return this._snap[methodName].apply(this._snap, arguments);
    };
  }

  get key() {
    console.log('getting snapshot key');
    return this._ref.key;
  }

  get ref() {
    return new FireCryptReference(this._ref.ref);
  }

  val() {
    return utils.transformValue(this._path, this._snap.val(), utils.decrypt);
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
    childPath = utils.encryptPath(childPath.split('/'), utils.specForPath(this._path)).join('/');
    return this._snap.hasChild(childPath);
  }

  exportVal() {
    return utils.transformValue(this._path, this._snap.exportVal(), utils.decrypt);
  }
}
