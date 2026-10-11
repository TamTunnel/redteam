// Fixed: no dynamic code execution — data goes through JSON.parse and
// dynamic behavior dispatches through an explicit allowlist of functions.
const OPERATIONS = {
  upper: (s) => s.toUpperCase(),
  lower: (s) => s.toLowerCase(),
};

function runUserOp(payload, opName) {
  const data = JSON.parse(payload);
  const op = OPERATIONS[opName];
  if (!op) throw new Error(`unknown operation: ${opName}`);
  return op(String(data.value));
}

module.exports = { runUserOp };
