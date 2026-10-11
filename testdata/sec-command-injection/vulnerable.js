// Vulnerable: command string assembled from parts.
const { exec, spawn } = require("child_process");

function showLog(branch, cb) {
  exec("git log --oneline " + branch, cb);
}

function convert(input, output) {
  return spawn(`ffmpeg -i ${input} ${output}`);
}

module.exports = { showLog, convert };
