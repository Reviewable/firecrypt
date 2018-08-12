export default class FireCryptOnDisconnect {
  constructor(path, originalOnDisconnect, crypto) {
    this._path = path;
    this._crypto = crypto;
    this._originalOnDisconnect = originalOnDisconnect;
  }

  _interceptOnDisconnectWrite(methodName, originalArguments, argIndex) {
    const self = this;

    this[methodName] = function() {
      const args = Array.prototype.slice.call(originalArguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = self._crypto.transformValue(self._path, args[argIndex], 'encrypt');
      }

      return self._originalOnDisconnect[methodName].apply(self._originalOnDisconnect, args);
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
