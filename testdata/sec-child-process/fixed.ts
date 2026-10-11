// Fixed: no shell — argv arrays are passed directly to the executable.
import { execFile, execFileSync } from "child_process";

export function listDir(dir: string, cb: (e: Error | null, out: string) => void): void {
  execFile("ls", [dir], cb);
}

export function diskUsage(target: string): Buffer {
  return execFileSync("du", ["-sh", target]);
}
