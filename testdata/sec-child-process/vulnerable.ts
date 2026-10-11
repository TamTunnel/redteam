// Vulnerable: shell:true with (potentially) interpolated commands.
import { exec, execSync } from "child_process";

export function listDir(dir: string, cb: (e: Error | null, out: string) => void): void {
  exec("ls " + dir, { shell: true }, cb);
}

export function diskUsage(target: string): Buffer {
  return execSync("du -sh " + target, { shell: true });
}
