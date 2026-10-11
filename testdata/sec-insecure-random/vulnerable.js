// Vulnerable: predictable PRNG used for a session token.
function newSessionToken() {
  const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  return token;
}

module.exports = { newSessionToken };
