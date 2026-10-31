const jwt = require('jsonwebtoken');
const db = require('../database');

const JWT_SECRET = 'super-secret-jwt-key';

function logAudit(subject, endpoint, deviceId, result, reason) {
  const stmt = db.prepare('INSERT INTO AuditLog (subject, endpoint, device_id, result, reason) VALUES (?, ?, ?, ?, ?)');
  stmt.run(subject, endpoint, deviceId || 'UNKNOWN', result, reason);
}

function zeroTrustPolicy(req, res, next) {
  const endpoint = req.originalUrl;
  const authHeader = req.headers['authorization'];
  const deviceId = req.headers['x-device-id'];
  const subject = req.user ? req.user.sub : 'ANONYMOUS';

  // 1. Validasi Kehadiran Token & Device ID
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logAudit(subject, endpoint, deviceId, 'DENY', 'Missing or malformed Authorization header');
    return res.status(401).json({ error: 'Access Denied: Missing token' });
  }

  if (!deviceId) {
    logAudit(subject, endpoint, deviceId, 'DENY', 'Missing X-Device-ID header');
    return res.status(401).json({ error: 'Access Denied: Missing Device ID' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { sub: nim_nidn, role: '...', id: ... }

    // Bypass Policy Engine khusus untuk token antar-service (misal: saat finalisasi nilai)
    if (req.user.role === 'service') {
      logAudit(req.user.sub, endpoint, deviceId, 'ALLOW', 'Service-to-service communication granted');
      return next();
    }

    // 2. Validasi Perangkat (X-Device-ID cocok dengan DB milik user tersebut)
    const deviceCheck = db.prepare('SELECT * FROM Devices WHERE user_id = ? AND device_id = ?').get(req.user.id, deviceId);
    if (!deviceCheck) {
      logAudit(req.user.sub, endpoint, deviceId, 'DENY', 'Device ID mismatch or unauthorized device');
      return res.status(403).json({ error: 'Zero Trust Violation: Device not registered for this user' });
    }

    // 3. Otorisasi Objek & Kondisional Berbasis Peran
    const role = req.user.role;
    const method = req.method;

    // Aturan Jam Akses Dosen (07:00 - 21:00) untuk Modifikasi / Finalisasi Nilai
    // (Catatan: Jika ingin bebas menguji kapan saja, baris pengecekan jam ini bisa dilewati sementara)
    if (role === 'dosen' && (method === 'PUT' || endpoint.includes('finalisasi'))) {
      const currentHour = new Date().getHours();
      if (currentHour < 7 || currentHour >= 21) {
        logAudit(req.user.sub, endpoint, deviceId, 'DENY', `Access outside allowed hours (${currentHour}:00). Allowed: 07:00 - 21:00`);
        return res.status(403).json({ error: 'Zero Trust Policy: Dosen modification/finalization only allowed between 07:00 - 21:00' });
      }
    }

    // Jika lolos semua pemeriksaan Policy Engine
    logAudit(req.user.sub, endpoint, deviceId, 'ALLOW', 'Access granted by Policy Engine');
    next();

  } catch (err) {
    logAudit(subject, endpoint, deviceId, 'DENY', `Invalid or expired token: ${err.message}`);
    return res.status(401).json({ error: 'Access Denied: Invalid token' });
  }
}

module.exports = { zeroTrustPolicy, logAudit, JWT_SECRET };