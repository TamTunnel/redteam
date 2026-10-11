// Vulnerable: SQL built by concatenation / template interpolation.
function findUser(db, name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

function findById(db, id) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}

module.exports = { findUser, findById };

// Vulnerable: bare identifier carrying user input straight into the query.
function findRaw(db, req) {
  return db.query(req.query.id);
}
module.exports.findRaw = findRaw;
