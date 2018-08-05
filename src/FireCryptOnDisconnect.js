import * as crypto from './crypto';

export default class FireCryptOnDisconnect {
  constructor(path, originalOnDisconnect) {
    this._path = path;
    this._originalOnDisconnect = originalOnDisconnect;
  }

  _interceptOnDisconnectWrite(methodName, originalArguments, argIndex) {
    this[methodName] = function() {
      const args = Array.prototype.slice.call(originalArguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = crypto.transformValue(this._path, args[argIndex], crypto.encrypt);
      }

      return this._originalOnDisconnect[methodName].apply(this._originalOnDisconnect, args);
    };
  }

  set() {
    return this._interceptOnDisconnectWrite('set', arguments, 0);
  }

  update() {
    return this._interceptOnDisconnectWrite('update', arguments, 0);
  }

  remove() {
    return this._interceptOnDisconnectWrite('remove', arguments);
  }

  cancel() {
    return this._interceptOnDisconnectWrite('cancel', arguments);
  }
}
