// Archivo principal del servidor Node.js/Express (Refactorizado)

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');

// Importar Routers
const juegosRouter = require('./routes/juego');
const resenasRouter = require('./routes/reseña');

const app = express();
const PORT = 3000; // Puedes cambiar el puerto si es necesario

// --- CONFIGURACIÓN Y CONEXIÓN A MONGO ---
// Usar una sola declaración y una sola conexión para evitar conflictos

// Reemplaza <USERNAME>, <PASSWORD> y <DBNAME> con tus credenciales de MongoDB Atlas
const MONGODB_URL = 'mongodb+srv://jacobogarcesoquendo:aFJzVMGN3o7fA38A@cluster0.mqwbn.mongodb.net/brandonnahuelgonzalezalvez';

mongoose.connect(MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Conexión a MongoDB Atlas exitosa.'))
.catch(err => console.error('❌ Error de conexión a MongoDB:', err.message));

// Middleware
app.use(cors()); // Permite solicitudes desde el frontend React
app.use(bodyParser.json());

// --- MONTAJE DE RUTAS ---
app.use('/api/juegos', juegosRouter);
app.use('/api/reseñas', resenasRouter);


// --- INICIO DEL SERVIDOR ---

app.listen(PORT, () => {
    console.log(`🚀 Servidor Express para PLUS ULTRA corriendo en http://localhost:${PORT}`);
});