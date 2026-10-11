// Vulnerable: user-controlled path segments reach the filesystem.
import * as fs from "fs";
import * as path from "path";

const BASE = "/var/app/data";

export function readUpload(name: string, cb: (e: Error | null, data: string) => void): void {
  fs.readFile(path.join(BASE, name), "utf8", cb);
}

export function readConfig(name: string): string {
  return fs.readFileSync("/etc/app/" + name, "utf8");
}
