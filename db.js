const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');

const db = new sqlite3.Database(path.join(__dirname, 'bar.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'boss', 'employee')) NOT NULL,
    full_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    total_price REAL NOT NULL,
    sale_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  )`);

  db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
    if (row.count === 0) {
      const saltRounds = 10;
      bcrypt.hash('admin123', saltRounds, (err, hashAdmin) => {
        bcrypt.hash('boss123', saltRounds, (err, hashBoss) => {
          bcrypt.hash('emp123', saltRounds, (err, hashEmp) => {
            db.run(`INSERT INTO users (username, password, role, full_name) VALUES 
              ('admin', ?, 'admin', 'Administrateur'),
              ('boss', ?, 'boss', 'Patron'),
              ('emp', ?, 'employee', 'Jean Employé')`,
              [hashAdmin, hashBoss, hashEmp]);
          });
        });
      });
    }
  });

  db.get(`SELECT COUNT(*) as count FROM products`, (err, row) => {
    if (row.count === 0) {
      db.run(`INSERT INTO products (name, price, stock) VALUES 
        ('Bière pression', 5.0, 100),
        ('Mojito', 8.0, 50),
        ('Coca-Cola', 3.0, 80),
        ('Planche de fromages', 12.0, 20),
        ('Vin rouge (verre)', 6.0, 40)`);
    }
  });
});

module.exports = db;