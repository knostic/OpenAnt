const sqlite3 = require("sqlite3");

function getConnection() {
  return new sqlite3.Database("app.db");
}

async function getUser(id) {
  const db = getConnection();
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
      db.close();
      if (err) reject(err);
      else resolve(row || null);
    });
  });
}

async function createUser(name) {
  const db = getConnection();
  return new Promise((resolve, reject) => {
    db.run("INSERT INTO users (name) VALUES (?)", [name], function (err) {
      db.close();
      if (err) reject(err);
      else resolve({ id: this.lastID, name });
    });
  });
}

module.exports = { getUser, createUser, getConnection };
