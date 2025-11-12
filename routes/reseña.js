const express = require('express');
const router = express.Router();
const Reseña = require('../models/reseña');

// POST /api/reseñas - Escribir nueva reseña
router.post('/', async (req, res) => {
    try {
        const nuevaReseña = new Reseña(req.body);
        await nuevaReseña.save();
        res.status(201).json(nuevaReseña);
    } catch (error) {
        res.status(400).json({ message: 'Error al crear reseña', error: error.message });
    }
});

// GET /api/reseñas - Obtener todas tus reseñas
router.get('/', async (req, res) => {
    try {
        // Popula para obtener el título y la imagen del juego asociado
        const reseñas = await Reseña.find().populate('juegoId', 'titulo imagenPortada');
        res.json(reseñas);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener reseñas', error: error.message });
    }
});

// GET /api/reseñas/juego/:juegoId - Reseñas de un juego específico
router.get('/juego/:juegoId', async (req, res) => {
    try {
        const reseñas = await Reseña.find({ juegoId: req.params.juegoId });
        res.json(reseñas);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener reseñas por juego', error: error.message });
    }
});

// PUT /api/reseñas/:id - Actualizar reseña existente
router.put('/:id', async (req, res) => {
    try {
        const reseñaActualizada = await Reseña.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!reseñaActualizada) return res.status(404).json({ message: 'Reseña no encontrada' });
        res.json(reseñaActualizada);
    } catch (error) {
        res.status(400).json({ message: 'Error al actualizar reseña', error: error.message });
    }
});

// DELETE /api/reseñas/:id - Eliminar reseña
router.delete('/:id', async (req, res) => {
    try {
        const reseñaEliminada = await Reseña.findByIdAndDelete(req.params.id);
        if (!reseñaEliminada) return res.status(404).json({ message: 'Reseña no encontrada' });
        res.json({ message: 'Reseña eliminada correctamente' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar reseña', error: error.message });
    }
});

module.exports = router;