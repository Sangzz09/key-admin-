require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ================================================================
// STORAGE IN RAM
// ================================================================
// key => {
//   name, active, type (day/week/month/lifetime),
//   durationMs, uses, createdAt,
//   activatedAt, expiresAt, deviceId, deviceName
// }
const keys = new Map();

// ================================================================
// ADMIN AUTH
// ================================================================
function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  next();
}

// ================================================================
// DURATION MAP
// ================================================================
const DURATION = {
  day:      1 * 24 * 60 * 60 * 1000,
  week:     7 * 24 * 60 * 60 * 1000,
  month:   30 * 24 * 60 * 60 * 1000,
  lifetime: null,
};

// ================================================================
// [ADMIN] TẠO KEY
// POST /api/admin/create-key
// Header: x-admin-secret
// Body: { name, type: "day"|"week"|"month"|"lifetime" }
// ================================================================
app.post('/api/admin/create-key', adminAuth, (req, res) => {
  const { name, type } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ success: false, message: 'name là bắt buộc' });
  }
  if (!DURATION.hasOwnProperty(type)) {
    return res.status(400).json({ success: false, message: 'type phải là: day, week, month, lifetime' });
  }

  const key = 'SK-' + crypto.randomBytes(16).toString('hex').toUpperCase();

  keys.set(key, {
    name: name.trim(),
    type,
    active: true,
    uses: 0,
    createdAt: new Date(),
    activatedAt: null,
    expiresAt: null,       // tính khi user DÙNG lần đầu
    deviceId: null,
    deviceName: null,
  });

  res.status(201).json({
    success: true,
    message: 'Tạo key thành công',
    key,
    name: name.trim(),
    type,
  });
});

// ================================================================
// [ADMIN] DANH SÁCH KEY
// GET /api/admin/keys
// ================================================================
app.get('/api/admin/keys', adminAuth, (req, res) => {
  const data = [];
  const now = new Date();
  for (const [key, info] of keys.entries()) {
    const expired = info.expiresAt ? now > info.expiresAt : false;
    data.push({
      key,
      name: info.name,
      type: info.type,
      active: info.active,
      uses: info.uses,
      createdAt: info.createdAt,
      activatedAt: info.activatedAt,
      expiresAt: info.expiresAt,
      deviceName: info.deviceName,
      expired,
      status: !info.active ? 'revoked' : expired ? 'expired' : info.activatedAt ? 'active' : 'unused',
    });
  }
  data.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, total: data.length, keys: data });
});

// ================================================================
// [ADMIN] VÔ HIỆU HOÁ KEY
// PATCH /api/admin/revoke-key
// Body: { key }
// ================================================================
app.patch('/api/admin/revoke-key', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  const info = keys.get(key);
  if (!info) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  info.active = false;
  res.json({ success: true, message: 'Key đã bị vô hiệu hoá' });
});

// ================================================================
// [ADMIN] XOÁ KEY
// DELETE /api/admin/delete-key
// Body: { key }
// ================================================================
app.delete('/api/admin/delete-key', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  if (!keys.has(key)) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  keys.delete(key);
  res.json({ success: true, message: 'Key đã bị xoá' });
});

// ================================================================
// [PUBLIC] XÁC THỰC KEY
// POST /api/verify
// Body: { key, deviceId, deviceName }
//   deviceId   - unique ID của thiết bị (client tự tạo & lưu)
//   deviceName - tên thiết bị (client lấy từ navigator)
// ================================================================
app.post('/api/verify', (req, res) => {
  const { key, deviceId, deviceName } = req.body;

  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });
  if (!deviceId) return res.status(400).json({ success: false, message: 'deviceId là bắt buộc' });

  const info = keys.get(key);

  if (!info) return res.status(401).json({ success: false, message: 'Key không hợp lệ' });
  if (!info.active) return res.status(403).json({ success: false, message: 'Key đã bị vô hiệu hoá' });

  const now = new Date();

  // Nếu key đã được kích hoạt
  if (info.activatedAt) {
    // Kiểm tra đúng thiết bị không
    if (info.deviceId !== deviceId) {
      return res.status(403).json({
        success: false,
        message: 'Key này đã được dùng trên thiết bị khác',
        deviceName: info.deviceName,
      });
    }
    // Kiểm tra hết hạn
    if (info.expiresAt && now > info.expiresAt) {
      return res.status(403).json({ success: false, message: 'Key đã hết hạn' });
    }
  } else {
    // Lần đầu dùng — kích hoạt và gắn thiết bị
    info.activatedAt = now;
    info.deviceId = deviceId;
    info.deviceName = deviceName || 'Unknown Device';

    if (DURATION[info.type] !== null) {
      info.expiresAt = new Date(now.getTime() + DURATION[info.type]);
    } else {
      info.expiresAt = null; // lifetime
    }
  }

  info.uses += 1;

  res.json({
    success: true,
    message: 'Key hợp lệ',
    user: {
      name: info.name,
      type: info.type,
      uses: info.uses,
      activatedAt: info.activatedAt,
      expiresAt: info.expiresAt,
      deviceName: info.deviceName,
    },
  });
});

// ================================================================
// HEALTH
// ================================================================
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'KeyAuth API 🚀', totalKeys: keys.size });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
