import * as crypto from './crypto';
import FireCryptSnapshot from './FireCryptSnapshot';
import FireCryptReference from './FireCryptReference';

export default class FireCryptQuery {
  constructor(query, order, originalRef) {
    this._query = query;
    this._order = order || {};
    this._originalRef = originalRef || query;
  }

  get ref() {
    // TODO: do I need to pass this to FireCryptReference constructor? If so, why am I getting that error?
    // return new FireCryptReference(crypto.decryptRef(this._query.ref));
    return crypto.decryptRef(this._query.ref);
  }
  
  on(eventType, callback, cancelCallback, context) {
    wrapQueryCallback(callback);
    return this._originalRef.on.call(
      this._query, eventType, callback.firecryptCallback, cancelCallback, context);
  }

  off(eventType, callback, context) {
    if (callback && callback.firecryptCallback) callback = callback.firecryptCallback;
    return this._originalRef.off.call(this._query, eventType, callback, context);
  }

  once(eventType, successCallback, failureCallback, context) {
    wrapQueryCallback(successCallback);
    return this._originalRef.once.call(
      this._query, eventType, successCallback && successCallback.firecryptCallback, failureCallback,
      context
    ).then((snap) => {
      return new FireCryptSnapshot(snap);
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

  orderByPriority() {
    return this._orderBy('orderByPriority', 'priority');
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
      value = crypto.encrypt(value, getType(value), this._order[this._order.by + 'Encrypted']);
    }
    if (key !== undefined && this._order.keyEncrypted) {
      key = crypto.encrypt(key, 'string', this._order.keyEncrypted);
    }
    return new FireCryptQuery(this._originalRef.equalTo.call(this._query, value, key), this._order);
  }

  limitToFirst() {
    return this._delegate('limitToFirst', arguments);
  }

  limitToLast() {
    return this._delegate('limitToLast', arguments);
  }

  limit() {
    return this._delegate('limit', arguments);
  }

  ref() {
    return crypto.decryptRef(this._originalRef.ref.call(this._query));
  }

  _delegate(methodName, args) {
    return new FireCryptQuery(this._originalRef[methodName].apply(this._query, args), this._order);
  }

  _checkCanSort(hasExtraKey) {
    if (this._order.by === 'key' ?
        this._order.keyEncrypted :
        this._order.valueEncrypted || hasExtraKey && this._order.keyEncrypted) {
      throw new Error('Encrypted items cannot be ordered');
    }
  }

  _orderBy(methodName, by, childKey) {
    var def = crypto.specForPath(crypto.refToPath(this.ref));
    var order = {by: by}

    var encryptedChildKey;
    if (def) {
      var childPath = childKey && childKey.split('/');
      for (var subKey in def) {
        if (!def.hasOwnProperty(subKey)) continue;
        var subDef = def[subKey];
        if (subDef['.encrypt']) {
          if (subDef['.encrypt'].key) order.keyEncrypted = subDef['.encrypt'].key;
          if (subDef['.encrypt'].value) order.valueEncrypted = subDef['.encrypt'].value;
        }
        if (childKey) {
          var childDef = crypto.specForPath(childPath, subDef);
          if (childDef && childDef['.encrypt'] && childDef['.encrypt'].value) {
            order.childEncrypted = childDef['.encrypt'].value;
          }
          var encryptedChildKeyCandidate = crypto.encryptPath(childPath, subDef).join('/');
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
        this._originalRef[methodName].call(this._query, encryptedChildKey || childKey), order);
    } else {
      return new FireCryptQuery(this._originalRef[methodName].call(this._query), order);
    }
  }
}

function wrapQueryCallback(callback) {
  if (!callback || callback.firecryptCallback) return;
  var wrappedCallback = function(snap, previousChildKey) {
    return callback.call(this, new FireCryptSnapshot(snap), previousChildKey);
  };
  wrappedCallback.firecryptCallback = wrappedCallback;
  callback.firecryptCallback = wrappedCallback;
}
