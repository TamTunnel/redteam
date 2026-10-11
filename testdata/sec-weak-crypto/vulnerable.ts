// Vulnerable: broken hash and cipher.
import * as crypto from "crypto";

export function hashPassword(pw: string): string {
  return crypto.createHash("md5").update(pw).digest("hex");
}

export function legacyDecrypt(data: string, key: string): string {
  const decipher = crypto.createDecipher("des", key);
  return decipher.update(data, "hex", "utf8");
}
