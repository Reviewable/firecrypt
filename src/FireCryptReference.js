import * as crypto from './crypto';
import FireCryptQuery from './FireCryptQuery';
import FireCryptSnapshot from './FireCryptSnapshot';
import FireCryptOnDisconnect from './FireCryptOnDisconnect';

export default class FireCryptReference {
  constructor(ref) {
    this._ref = ref;

    this._interceptPush();
    this._interceptTransaction();
    this._interceptOnDisconnect();

    [
      'on', 'off', 'once', 'orderByChild', 'orderByKey', 'orderByValue', 'startAt', 'endAt',
      'equalTo', 'limitToFirst', 'limitToLast'
    ].forEach((methodName) => {this._interceptQuery(methodName);});

    this._interceptWrite('set', 0);
    this._interceptWrite('remove');
    this._interceptWrite('update', 0);
    this._interceptWrite('setPriority');
    this._interceptWrite('setWithPriority', 0);

    if (ref.childrenKeys) {
      this._interceptChildrenKeys(ref);
    }
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
      return new FireCryptReference(this._ref.ref);
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
      return new FireCryptReference(this._ref.root);
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
      return new FireCryptReference(this._ref.parent);
    }
  }

  /**
   * Creates a new FireCryptReference object on a child of this one.
   * @param  {string} path The path to the desired child, relative to this reference.
   * @return {FireCryptReference} The child reference.
   */
  child(path) {
    return new FireCryptReference(this._ref.child(path));
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

  _interceptPush() {
    this.push = function() {
      const pushedRef = this._ref.push();

      const args = Array.prototype.slice.call(arguments);
      if (typeof args[0] !== 'undefined') {
        const encryptedRef = crypto.encryptRef(pushedRef);
        const path = crypto.refToPath(pushedRef);
      
        args[0] = crypto.transformValue(path, args[0], crypto.encrypt);
  
        pushedRef.set.apply(encryptedRef, args);
      }
      
      const decryptedPushedRef = new FireCryptReference(crypto.decryptRef(pushedRef));
      decryptedPushedRef.then = pushedRef.then;
      decryptedPushedRef.catch = pushedRef.catch;
      if (pushedRef.finally) decryptedPushedRef.finally = pushedRef.finally;

      return decryptedPushedRef;
    };
  }
  
  _interceptWrite(methodName, argIndex) {
    this[methodName] = function() {
      const encryptedRef = crypto.encryptRef(this._ref);
      const path = crypto.refToPath(this._ref);
  
      const args = Array.prototype.slice.call(arguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = crypto.transformValue(path, args[argIndex], crypto.encrypt);
      }
  
      return this._ref[methodName].apply(encryptedRef, args);
    };
  }
  
  _interceptChildrenKeys() {
    this.childrenKeys = function() {
      const encryptedRef = crypto.encryptRef(this._ref);
      return this._ref.childrenKeys.apply(encryptedRef, arguments).then((keys) => {
        if (!keys.some((key) => /\x91/.test(key))) {
          return keys;
        }
        return keys.map(crypto.decrypt);
      });
    };
  }

  _interceptOnDisconnect() {
    this.onDisconnect = function() {
      const encryptedRef = crypto.encryptRef(this._ref);
      return new FireCryptOnDisconnect(encryptedRef, this._ref.onDisconnect.call(encryptedRef));
    };
  }
  
  _interceptQuery(methodName) {
    this[methodName] = function() {
      const encryptedRef = crypto.encryptRef(this._ref);
      const query = new FireCryptQuery(encryptedRef, {}, this._ref);
      return query[methodName].apply(query, arguments);
    }
  }

  _interceptTransaction() {
    this.transaction = function() {
      const encryptedRef = crypto.encryptRef(this._ref);
      const path = crypto.refToPath(this._ref);

      const args = Array.prototype.slice.call(arguments);
      const originalCompute = args[0];
      args[0] = originalCompute && function(value) {
        value = crypto.transformValue(path, value, crypto.decrypt);
        value = originalCompute(value);
        value = crypto.transformValue(path, value, crypto.encrypt);
        return value;
      };
      if (args.length > 1) {
        const originalOnComplete = args[1];
        args[1] = originalOnComplete && function(error, committed, snapshot) {
          return originalOnComplete(error, committed, snapshot && new FireCryptSnapshot(snapshot));
        };
      }
      return this._ref.transaction.apply(encryptedRef, args).then(function(result) {
        result.snapshot = result.snapshot && new FireCryptSnapshot(result.snapshot);
        return result;
      });
    };
  }
}
