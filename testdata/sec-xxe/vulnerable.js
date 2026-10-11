// Vulnerable: xml2js parses attacker XML with default options.
const xml2js = require("xml2js");

function parseUpload(xmlData, cb) {
  xml2js.parseString(xmlData, cb);
}

module.exports = { parseUpload };
