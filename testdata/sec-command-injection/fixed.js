// Fixed: argv arrays — no shell, no string assembly.
const { execFile, spawn } = require("child_process");

function showLog(branch, cb) {
  execFile("git", ["log", "--oneline", branch], cb);
}

function convert(input, output) {
  return spawn("ffmpeg", ["-i", input, output]);
}

module.exports = { showLog, convert };
