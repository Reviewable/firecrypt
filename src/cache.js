const configurations = new Map();

function sizeCalculation(value, key) {
  return key.length + (typeof value === 'string' ? value.length : 4);
}

export function acquireCaches(options, keyHash) {
  if (typeof lrucache === 'undefined') return undefined;
  const {encryption, compression, encryptionCacheSize, decryptionCacheSize} = options;
  const compressionConfig = compression === 'deflate' ? [
    options.compressionThreshold, options.compressionOptions.level, options.compressionOptions.mem,
    options.compressionOptions.dictionary || null
  ] : null;
  const key = JSON.stringify([
    encryption, keyHash, compression, compressionConfig, encryptionCacheSize, decryptionCacheSize
  ]);
  let pair = configurations.get(key);
  if (!pair) {
    pair = {
      key,
      users: 0,
      encryption: new lrucache.LRUCache({maxSize: encryptionCacheSize, sizeCalculation}),
      decryption: new lrucache.LRUCache({maxSize: decryptionCacheSize, sizeCalculation}),
    };
    configurations.set(key, pair);
  }
  pair.users++;
  return pair;
}

export function releaseCaches(pair) {
  if (!pair || --pair.users) return;
  pair.encryption.clear();
  pair.decryption.clear();
  configurations.delete(pair.key);
}

function getCacheStats(cache) {
  return {
    count: cache.size,
    calculatedSize: cache.calculatedSize,
    capacity: cache.maxSize,
    utilization: cache.calculatedSize / cache.maxSize,
  };
}

export function getCachePairStats(pair) {
  if (!pair) return undefined;
  return {
    encryption: getCacheStats(pair.encryption),
    decryption: getCacheStats(pair.decryption),
  };
}

export function getFireCryptCacheStats() {
  return Array.from(configurations.values(), getCachePairStats);
}
