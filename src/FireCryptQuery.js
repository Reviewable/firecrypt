import FireCryptSnapshot from './FireCryptSnapshot';
import FireCryptReference from './FireCryptReference';

export default class FireCryptQuery {
  constructor(query, order, originalRef, firecrypt) {
    this._query = query;
    this._order = order || {};
    this._originalRef = originalRef || query;
    this._firecrypt = firecrypt;
  }

  _wrapQueryCallback(callback) {
    if (!callback || callback.firecryptCallback) return;
    const self = this;
    const wrappedCallback = function(snap, previousChildKey) {
      return callback.call(  // eslint-disable-next-line no-invalid-this
        this, new FireCryptSnapshot(snap, self._firecrypt), previousChildKey, self._firecrypt);
    };
    wrappedCallback.firecryptCallback = wrappedCallback;
    callback.firecryptCallback = wrappedCallback;
  }

  get ref() {
    return new FireCryptReference(
      this._firecrypt._crypto.decryptRef(this._query.ref), this._firecrypt);
  }

  on(eventType, callback, cancelCallback, context) {
    this._wrapQueryCallback(callback);
    return this._originalRef.on.call(
      this._query, eventType, callback.firecryptCallback, cancelCallback, context);
  }

  off(eventType, callback, context) {
    if (callback && callback.firecryptCallback) callback = callback.firecryptCallback;
    return this._originalRef.off.call(this._query, eventType, callback, context);
  }

  once(eventType, successCallback, failureCallback, context) {
    this._wrapQueryCallback(successCallback);
    return this._originalRef.once.call(
      this._query, eventType, successCallback && successCallback.firecryptCallback, failureCallback,
      context
    ).then((snap) => {
      return new FireCryptSnapshot(snap, this._firecrypt);
    });
  }

  orderByChild(key) {
    return this._orderBy('orderByChild', 'child', key);
  }

  orderByKey() {
    return this._orderBy('orderByKey', 'key');
  }

  orderByValue() {
    return this._orderBy('orderByValue', 'value');
  }

  startAt(value, key) {
    this._checkCanSort(key !== undefined);
    return this._delegate('startAt', arguments);
  }

  endAt(value, key) {
    this._checkCanSort(key !== undefined);
    return this._delegate('endAt', arguments);
  }

  equalTo(value, key) {
    if (this._order[this._order.by + 'Encrypted']) {
      value = this._firecrypt._crypto.encrypt(
        value, this._firecrypt._crypto.getType(value), this._order[this._order.by + 'Encrypted']);
    }
    if (key !== undefined && this._order.keyEncrypted) {
      key = this._firecrypt._crypto.encrypt(key, 'string', this._order.keyEncrypted);
    }
    return new FireCryptQuery(
      this._originalRef.equalTo.call(this._query, value, key), this._order, this._originalRef,
      this._firecrypt
    );
  }

  limitToFirst() {
    return this._delegate('limitToFirst', arguments);
  }

  limitToLast() {
    return this._delegate('limitToLast', arguments);
  }

  _delegate(methodName, args) {
    return new FireCryptQuery(
      this._originalRef[methodName].apply(this._query, args), this._order, this._originalRef,
      this._firecrypt
    );
  }

  _checkCanSort(hasExtraKey) {
    const orderedAndEncrypted = this._order.by === 'key' ?
      this._order.keyEncrypted :
      this._order.valueEncrypted || hasExtraKey && this._order.keyEncrypted;
    if (orderedAndEncrypted) throw new Error('Encrypted items cannot be ordered');
  }

  _orderBy(methodName, by, childKey) {
    const def = this._firecrypt._crypto.specForPath(this._firecrypt._crypto.refToPath(this.ref));
    const order = {by};

    let encryptedChildKey;
    if (def) {
      const childPath = childKey && childKey.split('/');
      for (const subKey in def) {
        if (!Object.prototype.hasOwnProperty.call(def, subKey)) continue;
        const subDef = def[subKey];
        if (subDef['.encrypt']) {
          if (subDef['.encrypt'].key) order.keyEncrypted = subDef['.encrypt'].key;
          if (subDef['.encrypt'].value) order.valueEncrypted = subDef['.encrypt'].value;
        }
        if (childKey) {
          const childDef = this._firecrypt._crypto.specForPath(childPath, subDef);
          if (childDef && childDef['.encrypt'] && childDef['.encrypt'].value) {
            order.childEncrypted = childDef['.encrypt'].value;
          }
          const encryptedChildKeyCandidate =
            this._firecrypt._crypto.encryptPath(childPath, subDef).join('/');
          if (encryptedChildKey && encryptedChildKeyCandidate !== encryptedChildKey) {
            throw new Error(
              'Incompatible encryption specifications for orderByChild("' + childKey + '")');
          }
          encryptedChildKey = encryptedChildKeyCandidate;
        }
      }
    }
    if (childKey) {
      return new FireCryptQuery(
        this._originalRef[methodName].call(this._query, encryptedChildKey || childKey), order,
        this._originalRef, this._firecrypt
      );
    }
    return new FireCryptQuery(
      this._originalRef[methodName].call(this._query), order, this._originalRef, this._firecrypt
    );
  }
}
