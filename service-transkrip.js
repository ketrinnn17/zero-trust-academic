const express = require('express');
const db = require('./database');
const { JWT_SECRET } = require('./middleware/policy');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SERVICE_SECRET = 'secret-key-gateway';

// D.1 Middleware Global Service Transkrip
app.use((req, res, next) => {
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (gatewaySecret !== SERVICE_SECRET) {
    return res.status(403).json({ error: 'Direct access forbidden: Missing or invalid Gateway Secret' });
  }

  const userHeader = req.headers['x-user'];
  if (userHeader) {
    req.user = JSON.parse(userHeader);
  }
  next();
});

// D.2 GET /transkrip/:nim: Akses Mahasiswa (NIM sendiri) & Admin (semua NIM)
app.get('/transkrip/:nim', (req, res) => {
  const { role, sub } = req.user;
  const targetNim = req.params.nim;

  if (role === 'mahasiswa' && sub !== targetNim) {
    return res.status(403).json({ error: 'Access denied: You can only view your own transcript' });
  }

  if (role !== 'admin' && role !== 'mahasiswa') {
    return res.status(403).json({ error: 'Unauthorized role for transcript access' });
  }

  const student = db.prepare('SELECT id FROM Users WHERE nim_nidn = ?').get(targetNim);
  if (!student) return res.status(404).json({ error: 'Student not found' });

  const transkrip = db.prepare('SELECT data_nilai FROM Transkrip WHERE mahasiswa_id = ?').get(student.id);
  if (!transkrip) return res.json({ nim: targetNim, transkrip: [] });

  res.json({ nim: targetNim, transkrip: JSON.parse(transkrip.data_nilai) });
});

// D.3 POST /transkrip/sinkron: HANYA menerima Token Service (role: 'service')
app.post('/transkrip/sinkron', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing service token' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Validasi ketat: Token wajib ber-role 'service'
    if (decoded.role !== 'service') {
      return res.status(403).json({ error: 'Zero Trust Violation: User tokens are strictly forbidden on this endpoint' });
    }

    const { kelas_id } = req.body;
    if (!kelas_id) return res.status(400).json({ error: 'kelas_id is required' });

    // Ambil seluruh nilai final pada kelas tersebut
    const listNilai = db.prepare('SELECT mahasiswa_id, nilai FROM Nilai WHERE kelas_id = ? AND status_final = 1').all(kelas_id);
    const kelasInfo = db.prepare('SELECT nama_kelas FROM Kelas WHERE id = ?').get(kelas_id);

    if (listNilai.length === 0) {
      return res.json({ message: 'No finalized grades found for this class' });
    }

    // Perbarui tabel Transkrip untuk setiap mahasiswa terkait
    const updateTransaction = db.transaction((grades) => {
      for (const item of grades) {
        let existing = db.prepare('SELECT data_nilai FROM Transkrip WHERE mahasiswa_id = ?').get(item.mahasiswa_id);
        let parsedData = existing ? JSON.parse(existing.data_nilai) : [];

        // Update atau tambahkan nilai kelas
        const index = parsedData.findIndex(d => d.kelas === kelasInfo.nama_kelas);
        if (index >= 0) {
          parsedData[index].nilai = item.nilai;
        } else {
          parsedData.push({ kelas: kelasInfo.nama_kelas, nilai: item.nilai });
        }

        if (existing) {
          db.prepare('UPDATE Transkrip SET data_nilai = ? WHERE mahasiswa_id = ?').run(JSON.stringify(parsedData), item.mahasiswa_id);
        } else {
          db.prepare('INSERT INTO Transkrip (mahasiswa_id, data_nilai) VALUES (?, ?)').run(item.mahasiswa_id, JSON.stringify(parsedData));
        }
      }
    });

    updateTransaction(listNilai);

    res.json({ message: 'Transcript synchronized successfully for class', kelas: kelasInfo.nama_kelas, updated_count: listNilai.length });

  } catch (err) {
    return res.status(401).json({ error: 'Invalid service token', details: err.message });
  }
});

app.listen(3002, () => {
  console.log('📜 Service Transkrip running on port 3002');
});