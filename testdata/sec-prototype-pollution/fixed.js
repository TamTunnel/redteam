// Fixed: Map for dynamic keys; no prototype mutation.
function merge(target, key, value) {
  const m = new Map(Object.entries(target));
  m.set(key, value);
  return Object.fromEntries(m);
}
module.exports = { merge };
