// Fixed: parser configured not to resolve external entities.
const { XMLParser } = require("fast-xml-parser");

const parser = new XMLParser({ processEntities: false, ignoreAttributes: false });

function parseUpload(xmlData) {
  return parser.parse(xmlData);
}

module.exports = { parseUpload };
