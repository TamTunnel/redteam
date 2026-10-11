// Fixed: this endpoint serves one fixed file — user input never becomes
// part of a filesystem path. (For dynamic names, map the input through an
// allowlist to fixed paths first, then read the resolved literal.)
const fs = require("fs");

function readDefaults(cb) {
  fs.readFile("/var/app/data/defaults.json", "utf8", cb);
}

module.exports = { readDefaults };
