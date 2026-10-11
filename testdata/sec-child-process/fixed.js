// Fixed: no shell — argv arrays are passed directly to the executable.
const { execFile, execFileSync } = require("child_process");

function listDir(dir, cb) {
  execFile("ls", [dir], cb);
}

function diskUsage(target) {
  return execFileSync("du", ["-sh", target]);
}

module.exports = { listDir, diskUsage };
