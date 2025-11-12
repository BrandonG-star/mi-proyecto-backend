const mongoose = require('mongoose');

// Esquema de Videojuegos (Games)
const JuegoSchema = new mongoose.Schema({
    titulo: { type: String, required: true, trim: true },
    genero: { type: String, required: true },
    plataforma: { type: String, required: true },
    añoLanzamiento: { type: Number, required: true },
    desarrollador: { type: String, required: true },
    imagenPortada: { type: String, default: 'https://placehold.co/600x400/1e293b/cbd5e1?text=PLUS+ULTRA+GAME' }, // Placeholder por defecto
    descripcion: { type: String, default: '' },
    completado: { type: Boolean, default: false },
    fechaCreacion: { type: Date, default: Date.now }
});

const Juego = mongoose.model('Juego', JuegoSchema);

module.exports = Juego;