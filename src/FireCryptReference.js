import FireCryptQuery from './FireCryptQuery';
import FireCryptSnapshot from './FireCryptSnapshot';
import FireCryptOnDisconnect from './FireCryptOnDisconnect';

export default class FireCryptReference {
  constructor(ref, crypto) {
    this._ref = ref;
    this._crypto = crypto;

    [
      'on', 'off', 'once', 'orderByChild', 'orderByKey', 'orderByValue', 'startAt', 'endAt',
      'equalTo', 'limitToFirst', 'limitToLast'
    ].forEach((methodName) => {this._interceptQuery(methodName);});
  }

  /**
   * Returns a placeholder value for auto-populating the current timestamp (time since the Unix
   * epoch, in milliseconds) as determined by the Firebase servers.
   * @return {Object} A timestamp placeholder value.
   */
  static get SERVER_TIMESTAMP() {
    return {
      '.sv': 'timestamp'
    };
  }

  /**
   * Returns the last part of this reference's path. The key of a root reference is `null`.
   * @return {string|null} The last part this reference's path.
   */
  get key() {
    return this._ref.key;
  }

  /**
   * Returns just the path component of the reference's URL.
   * @return {string} The path component of the Firebase URL wrapped by this reference.
   */
  get path() {
    return decodeURIComponent(this._ref.toString()).slice(this._ref.root.toString().length - 1);
  }

  /**
   * Returns a FireCryptReference at the same location as this query or reference.
   * @return {FireCryptReference|null} A FireCryptReference at the same location as this query or
   *     reference.
   */
  get ref() {
    if (this._ref.isEqual(this._ref.ref)) {
      return this;
    } else {
      return new FireCryptReference(this._ref.ref, this._crypto);
    }
  }

  /**
   * Returns a FireCryptReference reference to the root of the database.
   * @return {FireCryptReference} The root reference of the database.
   */
  get root() {
    if (this._ref.isEqual(this._ref.root)) {
      return this;
    } else {
      return new FireCryptReference(this._ref.root, this._crypto);
    }
  }

  /**
   * Returns a FireCryptReference to the parent location of this reference. The parent of a root
   * reference is `null`.
   * @return {FireCryptReference|null} The parent location of this reference.
   */
  get parent() {
    if (this._ref.parent === null) {
      return null;
    } else {
      return new FireCryptReference(this._ref.parent, this._crypto);
    }
  }

  /**
   * Creates a new FireCryptReference object on a child of this one.
   * @param  {string} path The path to the desired child, relative to this reference.
   * @return {FireCryptReference} The child reference.
   */
  child(path) {
    return new FireCryptReference(this._ref.child(path), this._crypto);
  }

  /**
   * Returns a JSON-serializable representation of this object.
   * @return {Object} A JSON-serializable representation of this object.
   */
  toJSON() {
    return this._ref.toJSON();
  }

  /**
   * Returns whether or not this FireCryptReference is equivalent to the provided FireCryptReference.
   * @return {FireCryptReference} Another FireCryptReference instance against which to compare.
   */
  isEqual(otherRef) {
    return this._ref.isEqual(otherRef._ref);
  }

  /**
   * Stringifies the wrapped reference.
   * @return {string} The Firebase URL wrapped by this FireCryptReference object.
   */
  toString() {
    return decodeURIComponent(this._ref.toString());
  }

  push() {
    const pushedRef = this._ref.push();

    const args = Array.prototype.slice.call(arguments);
    if (typeof args[0] !== 'undefined') {
      const encryptedRef = this._crypto.encryptRef(pushedRef);
      const path = this._crypto.refToPath(pushedRef);

      args[0] = this._crypto.transformValue(path, args[0], this._crypto.encrypt.bind(this._crypto));

      pushedRef.set.apply(encryptedRef, args);
    }

    const decryptedPushedRef = new FireCryptReference(this._crypto.decryptRef(pushedRef), this._crypto);
    decryptedPushedRef.then = pushedRef.then;
    decryptedPushedRef.catch = pushedRef.catch;
    if (pushedRef.finally) decryptedPushedRef.finally = pushedRef.finally;

    return decryptedPushedRef;
  }

  _interceptWrite(methodName, originalArguments, argIndex) {
    const encryptedRef = this._crypto.encryptRef(this._ref);

    const args = Array.prototype.slice.call(originalArguments);
    if (argIndex >= 0 && argIndex < args.length) {
      const path = this._crypto.refToPath(this._ref);
      args[argIndex] = this._crypto.transformValue(path, args[argIndex], this._crypto.encrypt.bind(this._crypto));
    }

    return this._ref[methodName].apply(encryptedRef, args);
  }

  set() {
    return this._interceptWrite('set', arguments, 0);
  }

  remove() {
    return this._interceptWrite('remove', arguments);
  }

  update() {
    return this._interceptWrite('update', arguments, 0);
  }

  childrenKeys() {
    if (!this._ref.childrenKeys) {
      throw new Error('childrenKeys() is not implemented.');
    }

    const encryptedRef = this._crypto.encryptRef(this._ref);
    return this._ref.childrenKeys.apply(encryptedRef, arguments).then((keys) => {
      if (!keys.some((key) => /\x91/.test(key))) {
        return keys;
      }
      return keys.map(this._crypto.decrypt.bind(this._crypto));
    });
  }

  onDisconnect() {
    const encryptedRef = this._crypto.encryptRef(this._ref);
    return new FireCryptOnDisconnect(encryptedRef, this._ref.onDisconnect.call(encryptedRef), this._crypto);
  }

  _interceptQuery(methodName) {
    const self = this;
    this[methodName] = function() {
      const encryptedRef = self._crypto.encryptRef(self._ref);
      const query = new FireCryptQuery(encryptedRef, {}, self._ref, self._crypto);
      return query[methodName].apply(query, arguments);
    }
  }

  transaction() {
    const self = this;

    const encryptedRef = this._crypto.encryptRef(this._ref);
    const path = this._crypto.refToPath(this._ref);

    const args = Array.prototype.slice.call(arguments);
    const originalCompute = args[0];
    args[0] = originalCompute && function(value) {
      value = self._crypto.transformValue(path, value, self._crypto.decrypt.bind(self._crypto));
      value = originalCompute(value);
      value = self._crypto.transformValue(path, value, self._crypto.encrypt.bind(self._crypto));
      return value;
    };
    if (args.length > 1) {
      const originalOnComplete = args[1];
      args[1] = originalOnComplete && function(error, committed, snapshot) {
        return originalOnComplete(error, committed, snapshot && new FireCryptSnapshot(snapshot));
      };
    }
    return this._ref.transaction.apply(encryptedRef, args).then((result) => {
      result.snapshot = result.snapshot && new FireCryptSnapshot(result.snapshot, this._crypto);
      return result;
    });
  };
}
