const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware: verificar JWT (copia ligera para este router)
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

// POST /api/friends/add - Agregar amigo por email/nickname/id
router.post('/add', authMiddleware, async (req, res) => {
  try {
    const { email, nickname, friendId } = req.body || {};
    let friend = null;

    if (friendId) {
      friend = await User.findById(friendId);
    } else if (email) {
      friend = await User.findOne({ email: String(email).toLowerCase() });
    } else if (nickname) {
      friend = await User.findOne({ nickname: String(nickname) });
    }

    if (!friend) return res.status(404).json({ message: 'Usuario no encontrado' });
    if (String(friend._id) === String(req.userId)) {
      return res.status(400).json({ message: 'No puedes agregarte a ti mismo' });
    }

    // Agregar a ambos (amistad mutua simple)
    await User.findByIdAndUpdate(req.userId, { $addToSet: { friends: friend._id } });
    await User.findByIdAndUpdate(friend._id, { $addToSet: { friends: req.userId } });

    const friendSummary = {
      id: friend._id,
      email: friend.email,
      nickname: friend.nickname,
      profilePicUrl: friend.profilePicUrl,
      phrase: friend.phrase,
    };

    res.json({ message: 'Amigo agregado', friend: friendSummary });
  } catch (err) {
    console.error('Error en /friends/add:', err);
    res.status(500).json({ message: 'Error al agregar amigo' });
  }
});

// GET /api/friends/list - Listar amigos del usuario autenticado
router.get('/list', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).populate('friends', 'email nickname profilePicUrl phrase');
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
    const friends = (user.friends || []).map(f => ({
      id: f._id,
      email: f.email,
      nickname: f.nickname,
      profilePicUrl: f.profilePicUrl,
      phrase: f.phrase,
    }));
    res.json({ friends });
  } catch (err) {
    console.error('Error en /friends/list:', err);
    res.status(500).json({ message: 'Error al listar amigos' });
  }
});

module.exports = router;