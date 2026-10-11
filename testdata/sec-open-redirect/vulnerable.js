// Vulnerable: redirect target comes from the request.
function login(req, res) {
  const next = req.query.next;
  res.redirect(next);
}

function go(dest) {
  window.location = dest;
}

module.exports = { login, go };
