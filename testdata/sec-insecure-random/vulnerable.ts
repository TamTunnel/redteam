// Vulnerable: predictable PRNG used for a session token.
export function newSessionToken(): string {
  const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  return token;
}
