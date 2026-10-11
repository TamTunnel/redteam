// Vulnerable: dynamic code execution on user-influenced input.
export function runUserCode(userInput: string, expr: string): unknown {
  const result: unknown = eval(userInput);
  const fn = new Function("return " + expr) as () => unknown;
  return fn();
}
