const express = require('express');
const db = require('./database');
const { JWT_SECRET } = require('./middleware/policy');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SERVICE_SECRET = 'secret-key-gateway';

// C.1 Middleware Global Service Nilai
app.use((req, res, next) => {
  const gatewaySecret = req.headers['x-gateway-secret'];
  
  if (!gatewaySecret || gatewaySecret !== SERVICE_SECRET) {
    return res.status(403).json({ error: 'Direct access forbidden: Missing or invalid Gateway Secret' });
  }

  // Verifikasi token dari header X-User yang dikirim Gateway
  const userHeader = req.headers['x-user'];
  if (userHeader) {
    try {
      req.user = JSON.parse(userHeader);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid user header format' });
    }
  }
  next();
});

// C.2 GET /nilai: Dosen (kelas diampu) & Mahasiswa (nilai sendiri)
app.get('/nilai', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized: User context missing' });
  }

  const { role, id, sub } = req.user;

  if (role === 'mahasiswa') {
    const nilai = db.prepare(`
      SELECT N.id, K.nama_kelas, N.nilai, N.status_final 
      FROM Nilai N JOIN Kelas K ON N.kelas_id = K.id 
      WHERE N.mahasiswa_id = ?
    `).all(id);
    return res.json({ user: sub, nilai });
  } 
  
  if (role === 'dosen') {
    const nilai = db.prepare(`
      SELECT N.id, K.nama_kelas, U.nim_nidn as mahasiswa_nim, N.nilai, N.status_final 
      FROM Nilai N 
      JOIN Kelas K ON N.kelas_id = K.id 
      JOIN Users U ON N.mahasiswa_id = U.id 
      WHERE K.dosen_id = ?
    `).all(id);
    return res.json({ dosen: sub, nilai });
  }

  if (role === 'admin') {
    const nilai = db.prepare(`
      SELECT N.id, K.nama_kelas, U.nim_nidn as mahasiswa_nim, N.nilai, N.status_final 
      FROM Nilai N 
      JOIN Kelas K ON N.kelas_id = K.id 
      JOIN Users U ON N.mahasiswa_id = U.id
    `).all();
    return res.json({ admin: sub, nilai });
  }

  res.status(403).json({ error: 'Unauthorized role' });
});

// C.3 PUT /nilai/:id: Dosen mengubah nilai (Syarat: belum final)
app.put('/nilai/:id', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized: User context missing' });

  const { role, id: userId } = req.user;
  const nilaiId = req.params.id;
  const { nilaiBaru } = req.body;

  if (role !== 'dosen') {
    return res.status(403).json({ error: 'Only lecturers can update grades' });
  }

  const row = db.prepare(`
    SELECT N.id, N.status_final, K.dosen_id 
    FROM Nilai N JOIN Kelas K ON N.kelas_id = K.id 
    WHERE N.id = ?
  `).get(nilaiId);

  if (!row) return res.status(404).json({ error: 'Grade record not found' });
  if (row.dosen_id !== userId) return res.status(403).json({ error: 'You do not teach this class' });
  if (row.status_final === 1) return res.status(400).json({ error: 'Grade is already finalized and cannot be modified' });

  db.prepare('UPDATE Nilai SET nilai = ? WHERE id = ?').run(nilaiBaru, nilaiId);
  res.json({ message: 'Grade updated successfully' });
});

// C.4 POST /kelas/:id/finalisasi: Dosen finalisasi kelas & sinkronisasi otomatis ke Transkrip via Gateway
app.post('/kelas/:id/finalisasi', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized: User context missing' });

  const { role, id: userId } = req.user;
  const kelasId = req.params.id;

  if (role !== 'dosen') {
    return res.status(403).json({ error: 'Only lecturers can finalize classes' });
  }

  const kelas = db.prepare('SELECT * FROM Kelas WHERE id = ? AND dosen_id = ?').get(kelasId, userId);
  if (!kelas) return res.status(403).json({ error: 'Class not found or not taught by you' });

  db.prepare('UPDATE Nilai SET status_final = 1 WHERE kelas_id = ?').run(kelasId);

  try {
    const tokenRes = await fetch('http://localhost:3000/auth/service', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: 'service-nilai', client_secret: SERVICE_SECRET })
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) throw new Error('Failed to acquire service token from Gateway');

    const syncRes = await fetch('http://localhost:3000/transkrip/sinkron', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenData.token}`,
        'X-Device-ID': 'internal-service-device'
      },
      body: JSON.stringify({ kelas_id: kelasId })
    });

    const syncData = await syncRes.json();
    res.json({ message: 'Class finalized and grades synchronized to transcripts successfully', syncResult: syncData });

  } catch (err) {
    res.status(500).json({ error: 'Finalized successfully, but transcript synchronization failed', details: err.message });
  }
});

app.listen(3001, () => {
  console.log('📊 Service Nilai running on port 3001');
});