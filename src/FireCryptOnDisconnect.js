import * as crypto from './crypto';

export default class FireCryptOnDisconnect {
  constructor(path, originalOnDisconnect) {
    this._path = path;
    this._originalOnDisconnect = originalOnDisconnect;

    this._interceptOnDisconnectWrite('set', 0);
    this._interceptOnDisconnectWrite('update', 0);
    this._interceptOnDisconnectWrite('remove');
    this._interceptOnDisconnectWrite('cancel');
  }

  _interceptOnDisconnectWrite(methodName, argIndex) {
    this[methodName] = function() {
      const args = Array.prototype.slice.call(arguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = crypto.transformValue(this._path, args[argIndex], crypto.encrypt);
      }

      return this._originalOnDisconnect[methodName].apply(this._originalOnDisconnect, args);
    };
  }
}
