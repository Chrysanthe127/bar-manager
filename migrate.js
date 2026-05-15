const sqlite3 = require('sqlite3');
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname, 'bar.db'));
db.run(`ALTER TABLE products ADD COLUMN cost_price REAL DEFAULT 0`, (err) => {
  if (err && !err.message.includes('duplicate column name')) console.log(err);
  else console.log('Colonne ajoutée');
  db.close();
});