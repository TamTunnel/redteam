// Fixed: CSPRNG-backed token.
import * as crypto from "crypto";

export function newSessionToken(): string {
  return crypto.randomUUID();
}
