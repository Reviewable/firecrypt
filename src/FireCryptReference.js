import * as crypto from './crypto';
import FireCryptQuery from './FireCryptQuery';
import FireCryptSnapshot from './FireCryptSnapshot';
import FireCryptOnDisconnect from './FireCryptOnDisconnect';

export default class FireCryptReference {
  constructor(ref) {
    this._ref = ref;

    this.get = ref.get;
    this.remove = ref.remove;

    this._interceptPush();
    this._interceptTransaction();
    this._interceptOnDisconnect();

    [
      'on', 'off', 'once', 'orderByChild', 'orderByKey', 'orderByValue', 'startAt', 'endAt',
      'equalTo', 'limitToFirst', 'limitToLast'
    ].forEach((methodName) => {this._interceptQuery(methodName);});

    this.set = this._interceptWrite(ref, 'set', 0);
    this.update = this._interceptWrite(ref, 'update', 0);
    this.setPriority = this._interceptWrite(ref, 'setPriority');
    this.setWithPriority = this._interceptWrite(ref, 'setWithPriority', 0);

    if (ref.childrenKeys) {
      this.childrenKeys = this._interceptChildrenKeys(ref);
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
    this.push = () => {
      // push() delegates to set(), which will take care of encrypting the ref and the argument.
      const pushedRef = this._ref.push.apply(this._ref, arguments);
      const decryptedRef = crypto.decryptRef(pushedRef);
      decryptedRef.then = pushedRef.then;
      decryptedRef.catch = pushedRef.catch;
      if (pushedRef.finally) decryptedRef.finally = pushedRef.finally;
      // TODO: do I need to pass to constructor here?
      // return new FireCryptReference(decryptedRef);
      return decryptedRef;
    };
  }
  
  _interceptWrite(methodName, argIndex) {
    this[methodName] = () => {
      const encryptedRef = crypto.encryptRef(this._ref);
  
      const args = Array.prototype.slice.call(arguments);
      if (argIndex >= 0 && argIndex < args.length) {
        args[argIndex] = crypto.transformValue(crypto.refToPath(path), args[argIndex], encrypt);
      }
  
      return this._ref[methodName].apply(encryptedRef, args);
    };
  }
  
  _interceptChildrenKeys() {
    this.childrenKeys = () => {
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
    this.onDisconnect = () => {
      const encryptedRef = crypto.encryptRef(this._ref);
      return new FireCryptOnDisconnect(encryptedRef, this._ref.onDisconnect.call(encryptedRef));
    };
  }
  
  _interceptQuery(methodName) {
    this[methodName] = () => {
      const encryptedRef = crypto.encryptRef(this._ref);
      var query = new FireCryptQuery(encryptedRef, {}, this._ref);
      return query[methodName].apply(query, arguments);
    }
  }

  _interceptTransaction() {
    this.transaction = () => {
      var encryptedRef = crypto.encryptRef(this._ref);
      var args = Array.prototype.slice.call(arguments);
      var originalCompute = args[0];
      args[0] = originalCompute && function(value) {
        value = crypto.transformValue(path, value, crypto.decrypt);
        value = originalCompute(value);
        value = crypto.transformValue(path, value, crypto.encrypt);
        return value;
      };
      if (args.length > 1) {
        var originalOnComplete = args[1];
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
