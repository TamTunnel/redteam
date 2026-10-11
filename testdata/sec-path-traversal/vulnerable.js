// Vulnerable: user-controlled path segments reach the filesystem.
const fs = require("fs");
const path = require("path");

const BASE = "/var/app/data";

function readUpload(name, cb) {
  fs.readFile(path.join(BASE, name), "utf8", cb);
}

function readConfig(name) {
  return fs.readFileSync("/etc/app/" + name, "utf8");
}

module.exports = { readUpload, readConfig };

// Vulnerable: .replace("../", "") only strips the FIRST occurrence —
// ".../...//" sails through. A naive sanitizer, not a fix.
function readNaive(name, cb) {
  fs.readFile("/var/app/data/" + name.replace("../", ""), "utf8", cb);
}
module.exports.readNaive = readNaive;
