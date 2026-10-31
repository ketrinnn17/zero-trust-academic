const db = require('./database');
const bcrypt = require('bcrypt');

const saltRounds = 10;
const hashedPassword = bcrypt.hashSync('password123', saltRounds);

console.log('🌱 Seeding database...');

db.transaction(() => {
  // Clear existing data
  db.exec('DELETE FROM AuditLog; DELETE FROM Transkrip; DELETE FROM Nilai; DELETE FROM Kelas; DELETE FROM Devices; DELETE FROM RefreshTokens; DELETE FROM Users;');

  // Users: 1 Admin (admin01), 2 Dosen (dosen01, dosen02), 3 Mahasiswa (mhs01, mhs02, mhs03)
  const insertUser = db.prepare('INSERT INTO Users (nim_nidn, password, role) VALUES (?, ?, ?)');
  const adminId = insertUser.run('admin01', hashedPassword, 'admin').lastInsertRowid;
  const dosen1Id = insertUser.run('dosen01', hashedPassword, 'dosen').lastInsertRowid;
  const dosen2Id = insertUser.run('dosen02', hashedPassword, 'dosen').lastInsertRowid;
  const mhs1Id = insertUser.run('mhs01', hashedPassword, 'mahasiswa').lastInsertRowid;
  const mhs2Id = insertUser.run('mhs02', hashedPassword, 'mahasiswa').lastInsertRowid;
  const mhs3Id = insertUser.run('mhs03', hashedPassword, 'mahasiswa').lastInsertRowid;

  // Devices: Wajib 1 device per user
  const insertDevice = db.prepare('INSERT INTO Devices (user_id, device_id) VALUES (?, ?)');
  insertDevice.run(adminId, 'device-admin-01');
  insertDevice.run(dosen1Id, 'device-dosen-01');
  insertDevice.run(dosen2Id, 'device-dosen-02');
  insertDevice.run(mhs1Id, 'device-mhs-01');
  insertDevice.run(mhs2Id, 'device-mhs-02');
  insertDevice.run(mhs3Id, 'device-mhs-03');

  // Kelas: 2 Kelas diampu dosen berbeda
  const insertKelas = db.prepare('INSERT INTO Kelas (nama_kelas, dosen_id) VALUES (?, ?)');
  const kelas1Id = insertKelas.run('Pemrograman Web', dosen1Id).lastInsertRowid;
  const kelas2Id = insertKelas.run('Kecerdasan Buatan', dosen2Id).lastInsertRowid;

  // Nilai awal
  const insertNilai = db.prepare('INSERT INTO Nilai (kelas_id, mahasiswa_id, nilai, status_final) VALUES (?, ?, ?, ?)');
  insertNilai.run(kelas1Id, mhs1Id, 85, 0);
  insertNilai.run(kelas1Id, mhs2Id, 90, 0);
  insertNilai.run(kelas2Id, mhs2Id, 88, 0);
  insertNilai.run(kelas2Id, mhs3Id, 75, 0);

  // Transkrip awal
  const insertTranskrip = db.prepare('INSERT INTO Transkrip (mahasiswa_id, data_nilai) VALUES (?, ?)');
  insertTranskrip.run(mhs1Id, JSON.stringify([{ kelas: 'Pemrograman Web', nilai: 85 }]));
  insertTranskrip.run(mhs2Id, JSON.stringify([{ kelas: 'Pemrograman Web', nilai: 90 }, { kelas: 'Kecerdasan Buatan', nilai: 88 }]));
  insertTranskrip.run(mhs3Id, JSON.stringify([{ kelas: 'Kecerdasan Buatan', nilai: 75 }]));
})();

console.log('✅ Seeding selesai.');