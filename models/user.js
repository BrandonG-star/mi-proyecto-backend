const mongoose = require('mongoose');

// Esquema de Usuarios (Users)
const UserSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario', required: true },
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true }, 
    isActive: {type: Boolean, default: true},
    fechaCreacion: { type: Date, default: Date.now },
    fechaActualizacion: { type: Date, default: Date.now }
});

// Atualiza a data de atualização automaticamente antes de salvar
UserSchema.pre('save', function (next) {
    this.fechaActualizacion = new Date();
    next();
});

const User = mongoose.model('Usuario', UserSchema);

module.exports = Usuario;