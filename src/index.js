require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ================================================================
// KẾT NỐI MONGODB
// ================================================================
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => { console.error('❌ MongoDB error:', err); process.exit(1); });

// ================================================================
// SCHEMA
// ================================================================
const keySchema = new mongoose.Schema({
  key:         { type: String, required: true, unique: true },
  name:        { type: String, required: true },        // tên / ghi chú cho key
  active:      { type: Boolean, default: true },
  uses:        { type: Number, default: 0 },
  lastUsedAt:  { type: Date, default: null },
  expiresAt:   { type: Date, default: null },           // null = không hết hạn
  createdAt:   { type: Date, default: Date.now },
});

const Key = mongoose.model('Key', keySchema);

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

// ================================================================
// [ADMIN] TẠO KEY MỚI
// POST /api/admin/create-key
// Header : x-admin-secret: <ADMIN_SECRET>
// Body   : { "name": "Tên key", "expiresInDays": 30 }   (expiresInDays tuỳ chọn)
// ================================================================
app.post('/api/admin/create-key', adminAuth, async (req, res) => {
  const { name, expiresInDays } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ success: false, message: 'name là bắt buộc' });
  }

  const key = 'sk-' + crypto.randomBytes(24).toString('hex');

  let expiresAt = null;
  if (expiresInDays && Number(expiresInDays) > 0) {
    expiresAt = new Date(Date.now() + Number(expiresInDays) * 86400000);
  }

  await Key.create({ key, name: name.trim(), expiresAt });

  res.status(201).json({
    success: true,
    message: 'Tạo key thành công',
    key,          // ← copy key này về để dùng
    name,
    expiresAt,
  });
});

// ================================================================
// [ADMIN] DANH SÁCH KEY
// GET /api/admin/keys
// Header: x-admin-secret: <ADMIN_SECRET>
// ================================================================
app.get('/api/admin/keys', adminAuth, async (req, res) => {
  const keys = await Key.find().sort({ createdAt: -1 });

  const data = keys.map(k => ({
    id:         k._id,
    key:        k.key,
    name:       k.name,
    active:     k.active,
    uses:       k.uses,
    lastUsedAt: k.lastUsedAt,
    expiresAt:  k.expiresAt,
    expired:    k.expiresAt ? new Date() > k.expiresAt : false,
    createdAt:  k.createdAt,
  }));

  res.json({ success: true, total: data.length, keys: data });
});

// ================================================================
// [ADMIN] VÔ HIỆU HOÁ KEY
// PATCH /api/admin/revoke-key
// Header: x-admin-secret: <ADMIN_SECRET>
// Body  : { "key": "sk-..." }
// ================================================================
app.patch('/api/admin/revoke-key', adminAuth, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });

  const found = await Key.findOneAndUpdate({ key }, { active: false }, { new: true });
  if (!found) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });

  res.json({ success: true, message: 'Key đã bị vô hiệu hoá' });
});

// ================================================================
// [ADMIN] XOÁ KEY
// DELETE /api/admin/delete-key
// Header: x-admin-secret: <ADMIN_SECRET>
// Body  : { "key": "sk-..." }
// ================================================================
app.delete('/api/admin/delete-key', adminAuth, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });

  const found = await Key.findOneAndDelete({ key });
  if (!found) return res.status(404).json({ success: false, message: 'Không tìm thấy key' });

  res.json({ success: true, message: 'Key đã bị xoá' });
});

// ================================================================
// [PUBLIC] XÁC THỰC KEY — dùng endpoint này ở web của bạn để login
// POST /api/verify
// Body : { "key": "sk-..." }
// ================================================================
app.post('/api/verify', async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key là bắt buộc' });

  const found = await Key.findOne({ key });

  if (!found) {
    return res.status(401).json({ success: false, message: 'Key không hợp lệ' });
  }

  if (!found.active) {
    return res.status(403).json({ success: false, message: 'Key đã bị vô hiệu hoá' });
  }

  if (found.expiresAt && new Date() > found.expiresAt) {
    return res.status(403).json({ success: false, message: 'Key đã hết hạn' });
  }

  // Cập nhật lần dùng
  found.uses += 1;
  found.lastUsedAt = new Date();
  await found.save();

  res.json({
    success: true,
    message: 'Key hợp lệ',
    user: {
      name:      found.name,
      uses:      found.uses,
      expiresAt: found.expiresAt,
    },
  });
});

// ================================================================
// HEALTH CHECK
// ================================================================
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'KeyAuth API đang chạy 🚀' });
});

// ================================================================
// START SERVER
// ================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
