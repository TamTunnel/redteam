// Fixed: parser configured not to resolve external entities.
import { XMLParser } from "fast-xml-parser";

const parser = new XMLParser({ processEntities: false, ignoreAttributes: false });

export function parseUpload(xmlData: string): unknown {
  return parser.parse(xmlData);
}
