import FireCryptQuery from './FireCryptQuery';
import FireCryptSnapshot from './FireCryptSnapshot';
import FireCryptOnDisconnect from './FireCryptOnDisconnect';

let childrenKeysFromLib;
try {
  childrenKeysFromLib = require('firebase-childrenkeys');
} catch (e) {
  // Library is optional, so ignore any errors from failure to load it.
}

export default class FireCryptReference {
  constructor(ref, crypto) {
    this._ref = ref;
    this._crypto = crypto;
  }

  _interceptQuery(methodName, originalArguments) {
    const encryptedRef = this._crypto.encryptRef(this._ref);
    const query = new FireCryptQuery(encryptedRef, {}, this._ref, this._crypto);
    return query[methodName].apply(query, originalArguments);
  }

  _interceptWrite(methodName, originalArguments, argIndex) {
    const encryptedRef = this._crypto.encryptRef(this._ref);

    const args = Array.prototype.slice.call(originalArguments);
    if (argIndex >= 0 && argIndex < args.length) {
      const path = this._crypto.refToPath(this._ref);
      args[argIndex] = this._crypto.transformValue(path, args[argIndex], 'encrypt');
    }

    return this._ref[methodName].apply(encryptedRef, args);
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
    const pushedRef = this.child(this._ref.push().key);
    
    let promise;
    if (typeof arguments[0] === 'undefined') {
      // A bare pushed ref should also be thennable.
      promise = Promise.resolve();
    } else {
      promise = pushedRef.set.apply(pushedRef, arguments);
    }

    pushedRef.then = promise.then.bind(promise);
    pushedRef.catch = promise.catch.bind(promise);
    if (promise.finally) pushedRef.finally = promise.finally.bind(promise);

    return pushedRef;
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
    const originalMethod = this._ref.childrenKeys || childrenKeysFromLib;

    if (typeof originalMethod !== 'function') {
      throw new Error(
        `childrenKeys() is not implemented. You must either provide a Firebase Database Reference
        which implements childrenKeys() or npm install the firebase-children keys libary.`
      );
    }

    const encryptedRef = this._crypto.encryptRef(this._ref);
    return originalMethod.apply(encryptedRef, [encryptedRef, ...arguments]).then((keys) => {
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

  on() {
    return this._interceptQuery('on', arguments);
  }

  off() {
    return this._interceptQuery('off', arguments);
  }

  once() {
    return this._interceptQuery('once', arguments);
  }

  orderByChild() {
    return this._interceptQuery('orderByChild', arguments);
  }

  orderByKey() {
    return this._interceptQuery('orderByKey', arguments);
  }

  orderByValue() {
    return this._interceptQuery('orderByValue', arguments);
  }
  
  startAt() {
    return this._interceptQuery('startAt', arguments);
  }
  
  endAt() {
    return this._interceptQuery('endAt', arguments);
  }

  equalTo() {
    return this._interceptQuery('equalTo', arguments);
  }

  limitToFirst() {
    return this._interceptQuery('limitToFirst', arguments);
  }

  limitToLast() {
    return this._interceptQuery('limitToLast', arguments);
  }

  transaction() {
    const encryptedRef = this._crypto.encryptRef(this._ref);
    const path = this._crypto.refToPath(this._ref);

    const args = Array.prototype.slice.call(arguments);
    const originalCompute = args[0];
    args[0] = originalCompute && ((value) => {
      value = this._crypto.transformValue(path, value, 'decrypt');
      value = originalCompute(value);
      value = this._crypto.transformValue(path, value, 'encrypt');
      return value;
    });
    if (args.length > 1) {
      const originalOnComplete = args[1];
      args[1] = originalOnComplete && ((error, committed, snapshot) => {
        return originalOnComplete(error, committed, snapshot && new FireCryptSnapshot(snapshot));
      });
    }
    return this._ref.transaction.apply(encryptedRef, args).then((result) => {
      result.snapshot = result.snapshot && new FireCryptSnapshot(result.snapshot, this._crypto);
      return result;
    });
  };
}
