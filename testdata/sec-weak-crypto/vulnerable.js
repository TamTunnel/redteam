// Vulnerable: broken hash and cipher.
const crypto = require("crypto");

function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

function legacyDecrypt(data, key) {
  const decipher = crypto.createDecipher("des", key);
  return decipher.update(data, "hex", "utf8");
}

module.exports = { hashPassword, legacyDecrypt };
