// Fixed: CSPRNG-backed token.
const crypto = require("crypto");

function newSessionToken() {
  return crypto.randomUUID();
}

module.exports = { newSessionToken };
