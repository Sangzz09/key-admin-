require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ================================================================
// LƯU KEY TRONG RAM (không cần DB)
// ================================================================
const keys = new Map(); // key => { name, active, uses, lastUsedAt, expiresAt, createdAt }

// ================================================================
// MIDDLEWARE XÁC THỰC ADMIN
// ================================================================
function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  next();
}

// POST /api/admin/create-key
app.post('/api/admin/create-key', adminAuth, (req, res) => {
  const { name, expiresInDays } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ success: false, message: 'name là bắt buộc' });
  }
  const key = 'sk-' + crypto.randomBytes(24).toString('hex');
  let expiresAt = null;
  if (expiresInDays && Number(expiresInDays) > 0) {
    expiresAt = new Date(Date.now() + Number(expiresInDays) * 86400000);
  }
  keys.set(key, { name: name.trim(), active: true, uses: 0, lastUsedAt: null, expiresAt, createdAt: new Date() });
  res.status(201).json({ success: true, message: 'Tạo key thành công', key, name: name.trim(), expiresAt });
});

// GET /api/admin/keys
app.get('/api/admin/keys', adminAuth, (req, res) => {
  const data = [];
  for (const [key, info] of keys.entries()) {
    data.push({ key, ...info, expired: info.expiresAt ? new Date() > info.expiresAt : false });
  }
  data.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, total: data.length, keys: data });
});

// PATCH /api/admin/revoke-key
app.patch('/api/admin/revoke-key', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  const info = keys.get(key);
  if (!info) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  info.active = false;
  res.json({ success: true, message: 'Key đã bị vô hiệu hoá' });
});

// DELETE /api/admin/delete-key
app.delete('/api/admin/delete-key', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  if (!keys.has(key)) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  keys.delete(key);
  res.json({ success: true, message: 'Key đã bị xoá' });
});

// POST /api/verify
app.post('/api/verify', (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  const info = keys.get(key);
  if (!info) return res.status(401).json({ success: false, message: 'Key không hợp lệ' });
  if (!info.active) return res.status(403).json({ success: false, message: 'Key đã bị vô hiệu hoá' });
  if (info.expiresAt && new Date() > info.expiresAt) return res.status(403).json({ success: false, message: 'Key đã hết hạn' });
  info.uses += 1;
  info.lastUsedAt = new Date();
  res.json({ success: true, message: 'Key hợp lệ', user: { name: info.name, uses: info.uses, expiresAt: info.expiresAt } });
});

// GET /
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'KeyAuth API đang chạy 🚀', totalKeys: keys.size });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
