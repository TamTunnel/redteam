// Fixed: JSON.parse for data, allowlisted dispatch for behavior.
const OPERATIONS: Record<string, (s: string) => string> = {
  upper: (s) => s.toUpperCase(),
  lower: (s) => s.toLowerCase(),
};

export function runUserOp(payload: string, opName: string): string {
  const data = JSON.parse(payload) as { value: unknown };
  const op = OPERATIONS[opName];
  if (!op) throw new Error(`unknown operation: ${opName}`);
  return op(String(data.value));
}
