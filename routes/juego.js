const express = require('express');
const router = express.Router();
const Juego = require('../models/juego');
const Reseña = require('../models/reseña'); // Necessário para exclusão em cascata
const Activity = require('../models/Activity');

// POST /api/juegos - Agregar juego
router.post('/', async (req, res) => {
    try {
        const nuevoJuego = new Juego(req.body);
        await nuevoJuego.save();
        const activity = new Activity({ 
            text: `¡Se añadió ${nuevoJuego.titulo} a la biblioteca!`, 
            gameId: nuevoJuego._id 
        });
        await activity.save();
        res.status(201).json(nuevoJuego);
    } catch (error) {
        res.status(400).json({ message: 'Error al agregar juego', error: error.message });
    }
});

// GET /api/juegos - Obtener todos los juegos (con filtros y ordenamiento)
router.get('/', async (req, res) => {
    try {
        // Implementación de Filtros y Búsqueda
        const { genero, plataforma, completado, busqueda, ordenarPor } = req.query;
        let query = {};

        if (genero) query.genero = genero;
        if (plataforma) query.plataforma = plataforma;
        if (completado !== undefined) query.completado = completado === 'true';
        if (busqueda) {
            query.$or = [
                { titulo: { $regex: busqueda, $options: 'i' } },
                { desarrollador: { $regex: busqueda, $options: 'i' } }
            ];
        }

        let sort = {};
        switch (ordenarPor) {
            case 'titulo': sort.titulo = 1; break;
            case 'fechaCreacion': sort.fechaCreacion = -1; break;
            case 'añoLanzamiento': sort.añoLanzamiento = -1; break;
            default: sort.fechaCreacion = -1;
        }

        const juegos = await Juego.find(query).sort(sort);
        res.json(juegos);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener juegos', error: error.message });
    }
});

// GET /api/juegos/:id - Obtener un juego específico
router.get('/:id', async (req, res) => {
    try {
        const juego = await Juego.findById(req.params.id);
        if (!juego) return res.status(404).json({ message: 'Juego no encontrado' });
        res.json(juego);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener juego', error: error.message });
    }
});

// PUT /api/juegos/:id - Actualizar información del juego
router.put('/:id', async (req, res) => {
    try {
        // Aseguramos que 'new: true' retorne el documento actualizado
        const juegoActualizado = await Juego.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!juegoActualizado) return res.status(404).json({ message: 'Juego no encontrado' });
        // Devolvemos el documento actualizado al cliente
        res.json(juegoActualizado);
    } catch (error) {
        res.status(400).json({ message: 'Error al actualizar juego', error: error.message });
    }
});

// DELETE /api/juegos/:id - Remover juego de tu biblioteca
router.delete('/:id', async (req, res) => {
    try {
        const juegoEliminado = await Juego.findByIdAndDelete(req.params.id);
        if (!juegoEliminado) return res.status(404).json({ message: 'Juego no encontrado' });

        // Eliminar também as reseñas asociadas
        await Reseña.deleteMany({ juegoId: req.params.id });

        res.json({ message: 'Juego y reseñas asociadas eliminados correctamente' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar juego', error: error.message });
    }
});

module.exports = router;