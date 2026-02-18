require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const keys = new Map();




const DURATION = {
  day:      1 * 24 * 60 * 60 * 1000,
  week:     7 * 24 * 60 * 60 * 1000,
  month:   30 * 24 * 60 * 60 * 1000,
  lifetime: null,
};

// Tạo key 10 ký tự ngẫu nhiên (chữ hoa + số)
function genKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = '';
  const bytes = crypto.randomBytes(10);
  for (let i = 0; i < 10; i++) {
    key += chars[bytes[i] % chars.length];
  }
  return key;
}

// POST /api/admin/create-key
app.post('/api/admin/create-key', (req, res) => {
  const { name, type } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ success: false, message: 'name là bắt buộc' });
  if (!DURATION.hasOwnProperty(type)) return res.status(400).json({ success: false, message: 'type phải là: day, week, month, lifetime' });

  // Tạo key không trùng
  let key;
  do { key = genKey(); } while (keys.has(key));

  keys.set(key, {
    name: name.trim(), type, active: true, uses: 0,
    createdAt: new Date(), activatedAt: null, expiresAt: null,
    deviceId: null, deviceName: null,
  });

  res.status(201).json({ success: true, message: 'Tạo key thành công', key, name: name.trim(), type });
});

// GET /api/admin/keys
app.get('/api/admin/keys', (req, res) => {
  const now = new Date();
  const data = [];
  for (const [key, info] of keys.entries()) {
    const expired = info.expiresAt ? now > info.expiresAt : false;
    data.push({
      key, name: info.name, type: info.type, active: info.active,
      uses: info.uses, createdAt: info.createdAt, activatedAt: info.activatedAt,
      expiresAt: info.expiresAt, deviceName: info.deviceName, expired,
      status: !info.active ? 'revoked' : expired ? 'expired' : info.activatedAt ? 'active' : 'unused',
    });
  }
  data.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, total: data.length, keys: data });
});

// PATCH /api/admin/revoke-key
app.patch('/api/admin/revoke-key', (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  const info = keys.get(key);
  if (!info) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  info.active = false;
  res.json({ success: true, message: 'Key đã bị vô hiệu hoá' });
});

// DELETE /api/admin/delete-key
app.delete('/api/admin/delete-key', (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  if (!keys.has(key)) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  keys.delete(key);
  res.json({ success: true, message: 'Key đã bị xoá' });
});

// POST /api/verify
app.post('/api/verify', (req, res) => {
  const { key, deviceId, deviceName } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  if (!deviceId) return res.status(400).json({ success: false, message: 'deviceId là bắt buộc' });

  const info = keys.get(key);
  if (!info) return res.status(401).json({ success: false, message: 'Key không hợp lệ' });
  if (!info.active) return res.status(403).json({ success: false, message: 'Key đã bị vô hiệu hoá' });

  const now = new Date();
  if (info.activatedAt) {
    if (info.deviceId !== deviceId) return res.status(403).json({ success: false, message: 'Key này đã được dùng trên thiết bị khác', deviceName: info.deviceName });
    if (info.expiresAt && now > info.expiresAt) return res.status(403).json({ success: false, message: 'Key đã hết hạn' });
  } else {
    info.activatedAt = now;
    info.deviceId = deviceId;
    info.deviceName = deviceName || 'Không rõ';
    if (DURATION[info.type] !== null) info.expiresAt = new Date(now.getTime() + DURATION[info.type]);
    else info.expiresAt = null;
  }

  info.uses += 1;
  res.json({ success: true, message: 'Key hợp lệ', user: { name: info.name, type: info.type, uses: info.uses, activatedAt: info.activatedAt, expiresAt: info.expiresAt, deviceName: info.deviceName } });
});

app.get('/', (req, res) => res.json({ status: 'ok', message: 'KeyAuth API 🚀', totalKeys: keys.size }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
