// Fixed: SHA-256 for integrity, AES-GCM for encryption.
const crypto = require("crypto");

function hashPassword(pw) {
  return crypto.createHash("sha256").update(pw).digest("hex");
}

function encrypt(data, key, iv) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
}

module.exports = { hashPassword, encrypt };
