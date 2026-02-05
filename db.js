const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      cpf TEXT NOT NULL UNIQUE,
      dob TEXT NOT NULL,
      email TEXT,
      email_verified INTEGER DEFAULT 0,
      email_verification_token TEXT,
      password_reset_token TEXT,
      password_reset_expires TEXT,
      password_hash TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      balance_cents INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      last_login_at TEXT
    )`
  );

  // Depósitos Pix
  db.run(
    `CREATE TABLE IF NOT EXISTS deposits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      amount_cents INTEGER NOT NULL,
      status TEXT NOT NULL,
      txid TEXT,
      provider TEXT,
      provider_payment_id TEXT,
      qr_code TEXT,
      qr_code_base64 TEXT,
      qr_code_image_url TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL,
      paid_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`
  );

  // Migração simples: tentar adicionar colunas se já existir tabela sem elas.
  const alterStatements = [
    "ALTER TABLE users ADD COLUMN email TEXT",
    "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN email_verification_token TEXT",
    "ALTER TABLE users ADD COLUMN password_reset_token TEXT",
    "ALTER TABLE users ADD COLUMN password_reset_expires TEXT",
    "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN balance_cents INTEGER DEFAULT 0"
  ];
  alterStatements.forEach((stmt) => {
    db.run(stmt, (err) => {
      // Ignorar erro se coluna já existir (SQLite retorna mensagem)
    });
  });

  // Migrações para tabela deposits (campos adicionais)
  const alterDeposits = [
    "ALTER TABLE deposits ADD COLUMN provider TEXT",
    "ALTER TABLE deposits ADD COLUMN provider_payment_id TEXT",
    "ALTER TABLE deposits ADD COLUMN qr_code TEXT",
    "ALTER TABLE deposits ADD COLUMN qr_code_base64 TEXT",
    "ALTER TABLE deposits ADD COLUMN qr_code_image_url TEXT",
    "ALTER TABLE deposits ADD COLUMN expires_at TEXT"
  ];
  alterDeposits.forEach((stmt) => {
    db.run(stmt, (err) => {
      // Ignorar erro se coluna já existir
    });
  });

  // Tabela de apostas (jogos)
  db.run(
    `CREATE TABLE IF NOT EXISTS bets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      game TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      state TEXT NOT NULL, -- in_progress | win | lose
      payout_cents INTEGER,
      created_at TEXT NOT NULL,
      finished_at TEXT,
      metadata_json TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`
  );
});

module.exports = db;
