require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Accès non autorisé' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Permission refusée' });
    }
    next();
  };
};

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Identifiants invalides' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Identifiants invalides' });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name } });
  });
});

app.get('/api/init-db', async (req, res) => {
  try {
    const hashAdmin = await bcrypt.hash('admin123', 10);
    const hashBoss = await bcrypt.hash('boss123', 10);
    const hashEmp = await bcrypt.hash('emp123', 10);
    db.run(`INSERT OR REPLACE INTO users (id, username, password, role, full_name) VALUES 
      (1, 'admin', ?, 'admin', 'Administrateur'),
      (2, 'boss', ?, 'boss', 'Patron'),
      (3, 'emp', ?, 'employee', 'Jean Employé')`, [hashAdmin, hashBoss, hashEmp], (err) => {
        if (err) res.status(500).json({ error: err.message });
        else res.json({ message: 'Utilisateurs créés/mis à jour' });
      });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/products', authenticate, (req, res) => {
  db.all(`SELECT * FROM products ORDER BY name`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// POST ajout produit (boss & admin)
// POST ajout produit
app.post('/api/products', authenticate, authorize('boss', 'admin'), (req, res) => {
  const { name, price, cost_price, stock } = req.body;
  if (!name || price === undefined) return res.status(400).json({ error: 'Nom et prix requis' });
  db.run(
    `INSERT INTO products (name, price, cost_price, stock) VALUES (?, ?, ?, ?)`,
    [name, price, cost_price || 0, stock || 0],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, name, price, cost_price: cost_price || 0, stock: stock || 0 });
    }
  );
});

// PUT modifier produit
app.put('/api/products/:id', authenticate, authorize('boss', 'admin'), (req, res) => {
  const { name, price, cost_price, stock } = req.body;
  db.run(
    `UPDATE products SET name = ?, price = ?, cost_price = ?, stock = ? WHERE id = ?`,
    [name, price, cost_price, stock, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Produit non trouvé' });
      res.json({ message: 'Produit mis à jour' });
    }
  );
});
app.delete('/api/products/:id', authenticate, authorize('boss', 'admin'), (req, res) => {
  db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Produit supprimé' });
  });
});

app.get('/api/sales', authenticate, (req, res) => {
  let query = `
    SELECT s.id, s.quantity, s.total_price, s.sale_time, 
           u.full_name as employee_name, p.name as product_name, p.price
    FROM sales s
    JOIN users u ON s.user_id = u.id
    JOIN products p ON s.product_id = p.id
  `;
  const params = [];
  if (req.user.role === 'employee') {
    query += ` WHERE s.user_id = ?`;
    params.push(req.user.id);
  }
  query += ` ORDER BY s.sale_time DESC`;
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/sales', authenticate, (req, res) => {
  const { product_id, quantity } = req.body;
  if (!product_id || !quantity || quantity <= 0) return res.status(400).json({ error: 'Données invalides' });
  db.get(`SELECT price, name FROM products WHERE id = ?`, [product_id], (err, product) => {
    if (err || !product) return res.status(404).json({ error: 'Produit inexistant' });
    const total_price = product.price * quantity;
    db.run(`INSERT INTO sales (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)`,
      [req.user.id, product_id, quantity, total_price], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, product_name: product.name, quantity, total_price });
      });
  });
});

app.get('/api/stats', authenticate, authorize('boss', 'admin'), (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  db.get(`SELECT SUM(total_price) as total_today FROM sales WHERE DATE(sale_time) = ?`, [today], (err, todayRow) => {
    db.get(`SELECT SUM(total_price) as total_week FROM sales WHERE sale_time >= datetime('now', '-7 days')`, (err, weekRow) => {
      db.get(`SELECT COUNT(*) as total_sales FROM sales`, (err, countRow) => {
        db.all(`SELECT u.full_name, SUM(s.total_price) as total FROM sales s JOIN users u ON s.user_id = u.id GROUP BY u.id ORDER BY total DESC`, (err, employeeStats) => {
          res.json({
            total_today: todayRow.total_today || 0,
            total_week: weekRow.total_week || 0,
            total_sales: countRow.total_sales || 0,
            employee_stats: employeeStats
          });
        });
      });
    });
  });
});

// ===== BÉNÉFICES / PERTES =====
app.get('/api/profit', authenticate, authorize('boss', 'admin'), (req, res) => {
  // Bénéfice total (ventes - coûts)
  const queryTotal = `
    SELECT SUM(s.total_price) as total_ca, 
           SUM(s.quantity * p.cost_price) as total_cost
    FROM sales s
    JOIN products p ON s.product_id = p.id
  `;
  db.get(queryTotal, [], (err, totalRow) => {
    if (err) return res.status(500).json({ error: err.message });
    const totalProfit = (totalRow.total_ca || 0) - (totalRow.total_cost || 0);

    // Bénéfice aujourd'hui
    const today = new Date().toISOString().slice(0, 10);
    db.get(`
      SELECT SUM(s.total_price) as ca_today, 
             SUM(s.quantity * p.cost_price) as cost_today
      FROM sales s
      JOIN products p ON s.product_id = p.id
      WHERE DATE(s.sale_time) = ?
    `, [today], (err, todayRow) => {
      const profitToday = (todayRow.ca_today || 0) - (todayRow.cost_today || 0);
      
      // Bénéfice cette semaine
      db.get(`
        SELECT SUM(s.total_price) as ca_week, 
               SUM(s.quantity * p.cost_price) as cost_week
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.sale_time >= datetime('now', '-7 days')
      `, [], (err, weekRow) => {
        const profitWeek = (weekRow.ca_week || 0) - (weekRow.cost_week || 0);
        
        // Marge brute moyenne (%)
        const marginRate = totalRow.total_ca > 0 ? ((totalProfit / totalRow.total_ca) * 100).toFixed(2) : 0;
        
        res.json({
          total_ca: totalRow.total_ca || 0,
          total_cost: totalRow.total_cost || 0,
          total_profit: totalProfit,
          profit_today: profitToday,
          profit_week: profitWeek,
          margin_rate: marginRate
        });
      });
    });
  });
});

app.get('/api/profit-by-product', authenticate, authorize('boss', 'admin'), (req, res) => {
  db.all(`
    SELECT p.id, p.name, p.price, p.cost_price,
           COALESCE(SUM(s.quantity), 0) as qty_sold,
           COALESCE(SUM(s.total_price), 0) as total_sales,
           COALESCE(SUM(s.quantity * p.cost_price), 0) as total_cost,
           COALESCE(SUM(s.total_price) - SUM(s.quantity * p.cost_price), 0) as profit
    FROM products p
    LEFT JOIN sales s ON p.id = s.product_id
    GROUP BY p.id
    ORDER BY profit DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
  // ===== CAPITAL INVESTI & RÉCAPITULATIF STOCK =====
app.get('/api/capital', authenticate, authorize('boss', 'admin'), (req, res) => {
  db.all(`SELECT name, stock, cost_price FROM products`, [], (err, products) => {
    if (err) return res.status(500).json({ error: err.message });
    let totalCapital = 0;
    let totalStockItems = 0;
    const productDetails = products.map(p => {
      const capital = p.stock * p.cost_price;
      totalCapital += capital;
      totalStockItems += p.stock;
      return { name: p.name, stock: p.stock, cost_price: p.cost_price, capital: capital };
    });
    res.json({
      total_capital: totalCapital,
      total_stock_items: totalStockItems,
      products: productDetails
    });
  });
});
});
app.get('/api/users', authenticate, authorize('admin'), (req, res) => {
  db.all(`SELECT id, username, role, full_name, created_at FROM users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users', authenticate, authorize('admin'), async (req, res) => {
  const { username, password, role, full_name } = req.body;
  if (!username || !password || !role || !full_name) return res.status(400).json({ error: 'Tous les champs requis' });
  const hashed = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)`, [username, hashed, role, full_name], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID });
  });
});

app.delete('/api/users/:id', authenticate, authorize('admin'), (req, res) => {
  db.run(`DELETE FROM users WHERE id = ? AND role != 'admin'`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Utilisateur supprimé' });
  });
});
// ===== MODIFICATION DU PROFIL UTILISATEUR (username, password) =====
app.put('/api/profile', authenticate, async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  const userId = req.user.id;

  // Vérifier que l'utilisateur existe
  db.get(`SELECT * FROM users WHERE id = ?`, [userId], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Utilisateur non trouvé' });

    // Si changement de nom d'utilisateur, vérifier qu'il n'est pas déjà pris
    if (username && username !== user.username) {
      const existing = await new Promise((resolve) => {
        db.get(`SELECT id FROM users WHERE username = ? AND id != ?`, [username, userId], (err, row) => resolve(row));
      });
      if (existing) return res.status(400).json({ error: 'Ce nom d\'utilisateur est déjà utilisé' });
    }

    // Si changement de mot de passe, vérifier l'ancien
    if (newPassword) {
      if (!oldPassword) return res.status(400).json({ error: 'Ancien mot de passe requis' });
      const valid = await bcrypt.compare(oldPassword, user.password);
      if (!valid) return res.status(401).json({ error: 'Ancien mot de passe incorrect' });
    }

    // Préparer la mise à jour
    let updates = [];
    let params = [];
    if (username && username !== user.username) {
      updates.push('username = ?');
      params.push(username);
    }
    if (newPassword) {
      const hashed = await bcrypt.hash(newPassword, 10);
      updates.push('password = ?');
      params.push(hashed);
    }
    if (updates.length === 0) return res.status(400).json({ error: 'Aucune modification demandée' });

    params.push(userId);
    db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      // Générer un nouveau token avec les nouvelles infos
      const newUserData = { id: user.id, username: username || user.username, role: user.role, full_name: user.full_name };
      const newToken = jwt.sign(newUserData, process.env.JWT_SECRET, { expiresIn: '8h' });
      res.json({ message: 'Profil mis à jour', token: newToken, user: newUserData });
    });
  });
});

app.get('/', (req, res) => {
  res.redirect('/login.html');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Serveur lancé sur le port ${port}`);
});
