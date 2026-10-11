// Vulnerable: nested quantifiers — catastrophic backtracking on crafted input.
const CLEANUP_RE = /(a+)+$/;

function makeSplitter(delim) {
  return new RegExp("(" + delim + "+)+");
}

module.exports = { CLEANUP_RE, makeSplitter };
