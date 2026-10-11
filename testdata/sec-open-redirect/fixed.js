// Fixed: fixed destinations only.
function login(req, res) {
  res.redirect("/dashboard");
}

function goHome() {
  window.location = "/home";
}

module.exports = { login, goHome };
