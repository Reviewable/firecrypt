const configurations = new Map();
const finalizers = typeof WeakRef === 'undefined' || typeof FinalizationRegistry === 'undefined' ?
  undefined : new FinalizationRegistry(({key, reference}) => {
    if (configurations.get(key) === reference) configurations.delete(key);
  });

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
  const existing = configurations.get(key);
  const pair = existing && existing.deref();
  if (pair) return pair;

  const newPair = {
    encryption: new lrucache.LRUCache({maxSize: encryptionCacheSize, sizeCalculation}),
    decryption: new lrucache.LRUCache({maxSize: decryptionCacheSize, sizeCalculation}),
  };
  if (finalizers) {
    // Crypto instances own the pair. The registry only lets another instance find it.
    const reference = new WeakRef(newPair);
    configurations.set(key, reference);
    finalizers.register(newPair, {key, reference});
  }
  return newPair;
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
  const stats = [];
  for (const reference of configurations.values()) {
    const pair = reference.deref();
    if (pair) stats.push(getCachePairStats(pair));
  }
  return stats;
}
