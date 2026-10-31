const Database = require('better-sqlite3');
const db = new Database('academic.db');

// Enable Foreign Keys
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nim_nidn TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'dosen', 'mahasiswa')) NOT NULL
  );

  CREATE TABLE IF NOT EXISTS Devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id TEXT UNIQUE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(id)
  );

  CREATE TABLE IF NOT EXISTS Kelas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nama_kelas TEXT NOT NULL,
    dosen_id INTEGER NOT NULL,
    FOREIGN KEY (dosen_id) REFERENCES Users(id)
  );

  CREATE TABLE IF NOT EXISTS Nilai (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kelas_id INTEGER NOT NULL,
    mahasiswa_id INTEGER NOT NULL,
    nilai REAL DEFAULT 0,
    status_final INTEGER DEFAULT 0,
    FOREIGN KEY (kelas_id) REFERENCES Kelas(id),
    FOREIGN KEY (mahasiswa_id) REFERENCES Users(id)
  );

  CREATE TABLE IF NOT EXISTS Transkrip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_id INTEGER UNIQUE NOT NULL,
    data_nilai TEXT NOT NULL,
    FOREIGN KEY (mahasiswa_id) REFERENCES Users(id)
  );

  CREATE TABLE IF NOT EXISTS RefreshTokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(id)
  );

  CREATE TABLE IF NOT EXISTS AuditLog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    waktu DATETIME DEFAULT CURRENT_TIMESTAMP,
    subject TEXT,
    endpoint TEXT,
    device_id TEXT,
    result TEXT CHECK(result IN ('ALLOW', 'DENY')),
    reason TEXT
  );
`);

module.exports = db;