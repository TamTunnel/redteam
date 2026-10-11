// Vulnerable: attacker-influenced key assigned to __proto__.
function merge(target, key, value) {
  target["__proto__"][key] = value;
}
function setProto(obj, payload) {
  obj.constructor.prototype.polluted = payload;
}
module.exports = { merge, setProto };
