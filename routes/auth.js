const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// Util: crear token JWT
function createToken(userId) {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET no está configurado en .env');
  }
  return jwt.sign({ userId }, secret, { expiresIn: '7d' });
}

// Middleware: verificar JWT
function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const parts = authHeader.split(' ');
    const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : null;
    if (!token) return res.status(401).json({ message: 'No autorizado' });
    const secret = process.env.JWT_SECRET;
    const payload = jwt.verify(token, secret);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Token inválido' });
  }
}

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: 'Email y contraseña son requeridos' });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ message: 'El email ya está registrado' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const nickname = email.split('@')[0];
    const user = await User.create({ email: email.toLowerCase(), passwordHash, nickname, profilePicUrl: '', phrase: '' });

    const token = createToken(user._id);
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        nickname: user.nickname,
        profilePicUrl: user.profilePicUrl,
        phrase: user.phrase,
      }
    });
  } catch (err) {
    if (err.message && err.message.includes('JWT_SECRET')) {
      return res.status(500).json({ message: err.message });
    }
    console.error('Error en /auth/register:', err);
    res.status(500).json({ message: 'Error al registrar usuario' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: 'Email y contraseña son requeridos' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const token = createToken(user._id);
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        nickname: user.nickname,
        profilePicUrl: user.profilePicUrl,
        phrase: user.phrase,
      }
    });
  } catch (err) {
    if (err.message && err.message.includes('JWT_SECRET')) {
      return res.status(500).json({ message: err.message });
    }
    console.error('Error en /auth/login:', err);
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
});

module.exports = router;

// --- NUEVO: Actualizar perfil del usuario autenticado ---
router.put('/profile', authMiddleware, async (req, res) => {
  try {
    const { profilePicUrl, nickname, phrase } = req.body || {};
    const updates = {};
    if (typeof profilePicUrl === 'string') updates.profilePicUrl = profilePicUrl;
    if (typeof nickname === 'string') updates.nickname = nickname;
    if (typeof phrase === 'string') updates.phrase = phrase;

    const user = await User.findByIdAndUpdate(req.userId, updates, { new: true });
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    res.json({
      user: {
        id: user._id,
        email: user.email,
        nickname: user.nickname,
        profilePicUrl: user.profilePicUrl,
        phrase: user.phrase,
      }
    });
  } catch (err) {
    console.error('Error en /auth/profile:', err);
    res.status(500).json({ message: 'Error al actualizar perfil' });
  }
});

// --- NUEVO: Subir foto de perfil ---
const ensureDir = (dirPath) => {
  try { fs.mkdirSync(dirPath, { recursive: true }); } catch (_) {}
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dest = path.join(__dirname, '..', 'uploads', 'avatars');
    ensureDir(dest);
    cb(null, dest);
  },
  filename: (req, file, cb) => {
    const ext = (file.mimetype === 'image/png') ? 'png'
      : (file.mimetype === 'image/webp') ? 'webp'
      : 'jpg';
    cb(null, `${req.userId}-${Date.now()}.${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Formato de imagen no soportado'));
    }
    cb(null, true);
  }
});

router.post('/profile/photo', authMiddleware, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No se recibió archivo' });
    const relativeUrl = `/uploads/avatars/${req.file.filename}`;
    const user = await User.findByIdAndUpdate(req.userId, { profilePicUrl: relativeUrl }, { new: true });
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
    res.json({
      user: {
        id: user._id,
        email: user.email,
        nickname: user.nickname,
        profilePicUrl: user.profilePicUrl,
        phrase: user.phrase,
      }
    });
  } catch (err) {
    console.error('Error en /auth/profile/photo:', err);
    res.status(500).json({ message: err.message || 'Error al subir foto' });
  }
});