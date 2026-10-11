// Fixed: SHA-256 for integrity, AES-GCM for encryption.
import * as crypto from "crypto";

export function hashPassword(pw: string): string {
  return crypto.createHash("sha256").update(pw).digest("hex");
}

export function encrypt(data: string, key: Buffer, iv: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
}
