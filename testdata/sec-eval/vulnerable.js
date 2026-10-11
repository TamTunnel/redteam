// Vulnerable: dynamic code execution on user-influenced input.
function runUserCode(userInput, expr) {
  const result = eval(userInput);
  const fn = new Function("return " + expr);
  return { result, fn: fn() };
}
module.exports = { runUserCode };

// Vulnerable: member-expression eval bypasses naive identifier-only checks.
function runGlobal(userInput) {
  return window.eval(userInput);
}
module.exports.runGlobal = runGlobal;
