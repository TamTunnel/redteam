// Vulnerable: shell:true with (potentially) interpolated commands.
const { exec } = require("child_process");
const child_process = require("child_process");

function listDir(dir, cb) {
  exec("ls " + dir, { shell: true }, cb);
}

function diskUsage(target) {
  return child_process.execSync("du -sh " + target, { shell: true });
}

module.exports = { listDir, diskUsage };
