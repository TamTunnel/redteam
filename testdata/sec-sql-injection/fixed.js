// Fixed: bound parameters — user input never touches the SQL text.
function findUser(db, name) {
  return db.query("SELECT * FROM users WHERE name = ?", [name]);
}

function findById(db, id) {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}

module.exports = { findUser, findById };
