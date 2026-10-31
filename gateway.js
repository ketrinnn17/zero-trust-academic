const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { createProxyMiddleware } = require('http-proxy-middleware');
const db = require('./database');
const { zeroTrustPolicy, logAudit, JWT_SECRET } = require('./middleware/policy');

const app = express();
app.use(express.json());

const SERVICE_SECRET = 'secret-key-gateway';

// B.1 POST /auth/login
app.post('/auth/login', (req, res) => {
  const { nim_nidn, password } = req.body;
  const deviceId = req.headers['x-device-id'];

  if (!nim_nidn || !password || !deviceId) {
    return res.status(400).json({ error: 'nim_nidn, password, and X-Device-ID header are required' });
  }

  const user = db.prepare('SELECT * FROM Users WHERE nim_nidn = ?').get(nim_nidn);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    logAudit(nim_nidn, '/auth/login', deviceId, 'DENY', 'Invalid credentials');
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Cek Device ID terdaftar untuk user ini
  const deviceCheck = db.prepare('SELECT * FROM Devices WHERE user_id = ? AND device_id = ?').get(user.id, deviceId);
  if (!deviceCheck) {
    logAudit(nim_nidn, '/auth/login', deviceId, 'DENY', 'Unauthorized device login attempt');
    return res.status(403).json({ error: 'Device not authorized for this user' });
  }

  // Generate JWT Access Token (10 menit)
  const accessToken = jwt.sign(
    { id: user.id, sub: user.nim_nidn, role: user.role },
    JWT_SECRET,
    { expiresIn: '10m' }
  );

  // Generate Refresh Token (1 hari)
  const refreshToken = jwt.sign(
    { id: user.id, sub: user.nim_nidn },
    JWT_SECRET,
    { expiresIn: '1d' }
  );

  db.prepare('INSERT INTO RefreshTokens (user_id, token) VALUES (?, ?)').run(user.id, refreshToken);

  logAudit(user.nim_nidn, '/auth/login', deviceId, 'ALLOW', 'Successful login');
  res.json({ accessToken, refreshToken });
});

// B.2 POST /auth/service (Endpoint generate token service khusus antar-service, berlaku 5 menit)
app.post('/auth/service', (req, res) => {
  const { client_id, client_secret } = req.body;
  
  // Validasi kredensial internal service
  if (client_id === 'service-nilai' && client_secret === SERVICE_SECRET) {
    const serviceToken = jwt.sign(
      { sub: 'service-nilai', role: 'service' },
      JWT_SECRET,
      { expiresIn: '5m' }
    );
    return res.json({ token: serviceToken });
  }

  res.status(401).json({ error: 'Invalid service credentials' });
});

// POST /auth/refresh (Memperbarui access token menggunakan refresh token)
app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  const deviceId = req.headers['x-device-id'];

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    
    const tokenRecord = db.prepare('SELECT * FROM RefreshTokens WHERE user_id = ? AND token = ?').get(decoded.id, refreshToken);
    if (!tokenRecord) {
      return res.status(403).json({ error: 'Invalid or revoked refresh token' });
    }

    const user = db.prepare('SELECT * FROM Users WHERE id = ?').get(decoded.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const newAccessToken = jwt.sign(
      { id: user.id, sub: user.nim_nidn, role: user.role },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired refresh token' });
  }
});

// POST /auth/logout (Menghapus refresh token dari database)
app.post('/auth/logout', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  db.prepare('DELETE FROM RefreshTokens WHERE token = ?').run(refreshToken);
  res.json({ message: 'Logged out successfully' });
});

// B.3 & B.4 & B.5 Menerapkan Policy Engine & Proxy ke Microservices dengan pathRewrite & Body Forwarding
// Route /nilai ke Port 3001
app.use('/nilai', zeroTrustPolicy, createProxyMiddleware({
  target: 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: {
    '^/': '/nilai/',
  },
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('X-Gateway-Secret', SERVICE_SECRET);
      if (req.user) {
        proxyReq.setHeader('X-User', JSON.stringify(req.user));
      }
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
    }
  }
}));

// Route /kelas ke Port 3001
app.use('/kelas', zeroTrustPolicy, createProxyMiddleware({
  target: 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: {
    '^/': '/kelas/',
  },
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('X-Gateway-Secret', SERVICE_SECRET);
      if (req.user) {
        proxyReq.setHeader('X-User', JSON.stringify(req.user));
      }
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
    }
  }
}));

// Route /transkrip ke Port 3002
app.use('/transkrip', zeroTrustPolicy, createProxyMiddleware({
  target: 'http://localhost:3002',
  changeOrigin: true,
  pathRewrite: {
    '^/': '/transkrip/',
  },
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('X-Gateway-Secret', SERVICE_SECRET);
      if (req.user) {
        proxyReq.setHeader('X-User', JSON.stringify(req.user));
      }
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
    }
  }
}));

app.listen(3000, () => {
  console.log('🚪 API Gateway running on port 3000');
});