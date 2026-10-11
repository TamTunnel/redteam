// Fixed: this endpoint serves one fixed file — user input never becomes
// part of a filesystem path.
import * as fs from "fs";

export function readDefaults(cb: (e: Error | null, data: string) => void): void {
  fs.readFile("/var/app/data/defaults.json", "utf8", cb);
}
