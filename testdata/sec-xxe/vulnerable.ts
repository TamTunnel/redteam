// Vulnerable: xml2js parses attacker XML with default options.
import * as xml2js from "xml2js";

export function parseUpload(xmlData: string, cb: (e: Error | null, r: unknown) => void): void {
  xml2js.parseString(xmlData, cb);
}
