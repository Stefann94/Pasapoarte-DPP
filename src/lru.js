/** Minimal LRU cache on top of Map's insertion order. */
export function createLru(max) {
  const map = new Map();
  return {
    get(key) {
      const v = map.get(key);
      if (v === undefined) return undefined;
      map.delete(key);
      map.set(key, v);
      return v;
    },
    set(key, value) {
      map.delete(key);
      map.set(key, value);
      if (map.size > max) map.delete(map.keys().next().value);
    },
    delete: (key) => map.delete(key),
    get size() {
      return map.size;
    },
  };
}
