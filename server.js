// Archivo principal del servidor Node.js/Express (Refactorizado)

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');

// Importar Routers
const juegosRouter = require('./routes/juego');
const resenasRouter = require('./routes/reseña');
const authRouter = require('./routes/auth');
const axios = require('axios');

// --- ¡NUEVO! Importa el nuevo modelo ---
const Activity = require('./models/Activity'); // Asumiendo que lo pusiste en /models/Activity.js

require('dotenv').config();
const Juego = require('./models/juego');
const Reseña = require('./models/reseña');

const app = express();
// Si usas variables de entorno, asegúrate de declararlas después de config()
const PORT = process.env.PORT || 3000;
// Ejemplo: const MONGO_URI = process.env.MONGO_URI;

// ¡RECUERDA ARREGLAR ESTA LÍNEA CON UNA DB QUE EXISTA!
const MONGODB_URL = 'mongodb+srv://jacobogarcesoquendo:aFJzVMGN3o7fA38A@cluster0.mqwbn.mongodb.net/brandonnahuelgonzalezalvez';

mongoose.connect(MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Conexión a MongoDB Atlas exitosa.'))
.catch(err => console.error('❌ Error de conexión a MongoDB:', err.message));

// --- (¡NUEVO!) RUTA PARA BUSCAR JUEGOS EN RAWG ---
// Ruta: /api/search-game/:title (mejora robustez y validación)
app.get('/api/search-game/:title', async (req, res) => {
  const raw = req.params.title || '';
  const title = encodeURIComponent(raw); // robustez ante caracteres especiales
  const API_KEY = process.env.RAWG_API_KEY;

  if (!API_KEY) {
    // Si falta la clave, devuelve 500 controlado con mensaje claro
    return res.status(500).json({ message: "RAWG_API_KEY no está configurado" });
  }

  const url = `https://api.rawg.io/api/games?key=${API_KEY}&search=${title}&page_size=5`;

  try {
    const response = await axios.get(url);
    const games = response.data?.results || [];
    const cleanedGames = games.map(game => ({
      id: game.id,
      name: game.name,
      background_image: game.background_image,
      released: game.released ? game.released.split('-')[0] : 'N/A',
    }));
    res.json(cleanedGames);
  } catch (error) {
    console.error("Error al buscar en RAWG:", error.message);
    // Devuelve 502 para distinguir error externo
    res.status(502).json({ message: "Error al contactar la API externa." });
  }
});

// --- ¡NUEVO! RUTA PARA EL FEED DE ACTIVIDAD ---
app.get('/api/feed', async (req, res) => {
    try {
        // Busca las 20 actividades más recientes y las ordena
        const activities = await Activity.find()
            .sort({ timestamp: -1 }) // -1 = descendente (la más nueva primero)
            .limit(20)
            .populate('gameId', 'titulo'); // Trae el 'titulo' del juego (asumiendo que el campo se llama 'titulo')
            
        res.json(activities);
    } catch (err) {
        res.status(500).json({ message: "Error al cargar el feed", error: err.message });
    }
});
app.get('/api/stats/dashboard', async (req, res) => {
    try {
        // 1. Estadísticas básicas (Total y Completados)
        // Usamos $group para agrupar todos los juegos en uno solo
        const basicStats = await Juego.aggregate([
            {
                $group: {
                    _id: null, // Agrupamos todo en un solo documento
                    totalJuegos: { $sum: 1 },
                    completados: { 
                        $sum: { $cond: ["$completado", 1, 0] } // Suma 1 si "completado" es true
                    }
                }
            }
        ]);

        // 2. Conteo de juegos por Plataforma (para el gráfico de Pie)
        const plataformaStats = await Juego.aggregate([
            { $group: { _id: "$plataforma", count: { $sum: 1 } } },
            { $sort: { count: -1 } } // Opcional: ordena del más jugado al menos
        ]);

        // 3. Conteo de juegos por Género (para el gráfico de Pie)
        const generoStats = await Juego.aggregate([
            { $group: { _id: "$genero", count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        // 4. Puntuación Media de todas las Reseñas
        const reseñaStats = await Reseña.aggregate([
            {
                $group: {
                    _id: null,
                    mediaPuntuacion: { $avg: "$puntuacion" }
                }
            }
        ]);

        // 5. Prepara el objeto de respuesta
        const stats = {
            totalJuegos: basicStats[0]?.totalJuegos || 0,
            completados: basicStats[0]?.completados || 0,
            plataformas: plataformaStats, // Ej: [{ _id: "PC", count: 5 }, { _id: "PS5", count: 2 }]
            generos: generoStats,
            mediaPuntuacion: reseñaStats[0]?.mediaPuntuacion || 0
        };

        res.json(stats);

    } catch (err) {
        console.error("Error al generar estadísticas:", err.message);
        res.status(500).json({ message: "Error al generar estadísticas", error: err.message });
    }
});


// Middleware
app.use(cors()); // Permite solicitudes desde el frontend React
app.use(bodyParser.json());

// --- MONTAJE DE RUTAS ---
app.use('/api/juegos', juegosRouter);
app.use('/api/reseñas', resenasRouter);
app.use('/api/auth', authRouter);


// --- INICIO DEL SERVIDOR ---

app.listen(PORT, () => {
    console.log(`🚀 Servidor Express para PLUS ULTRA corriendo en http://localhost:${PORT}`);
});