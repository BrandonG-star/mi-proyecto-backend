const mongoose = require('mongoose');

// Esquema de Reseñas (Reviews)
const ReseñaSchema = new mongoose.Schema({
    juegoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego', required: true },
    puntuacion: { type: Number, required: true, min: 1, max: 5 }, // 1-5 estrellas
    textoReseña: { type: String, required: true },
    horasJugadas: { type: Number, default: 0, min: 0 },
    dificultad: { type: String, enum: ["Fácil", "Normal", "Difícil"], default: "Normal" },
    recomendaria: { type: Boolean, required: true },
    fechaCreacion: { type: Date, default: Date.now },
    fechaActualizacion: { type: Date, default: Date.now }
});

// Atualiza a data de atualização automaticamente antes de salvar
ReseñaSchema.pre('save', function (next) {
    this.fechaActualizacion = new Date();
    next();
});

const Reseña = mongoose.model('Reseña', ReseñaSchema);

module.exports = Reseña;