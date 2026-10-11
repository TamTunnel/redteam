// Fixed: linear-time patterns, no nested quantifiers.
const USERNAME_RE = /^[a-z0-9_]+$/;

function makeSplitter(delim) {
  if (delim !== ",") throw new Error("unsupported delimiter");
  return /^[a-z,]+$/;
}

module.exports = { USERNAME_RE, makeSplitter };
