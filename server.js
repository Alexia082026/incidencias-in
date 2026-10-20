const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. MIDDLEWARES BÁSICOS
// ==========================================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Crear la carpeta 'uploads' si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Servir la carpeta de fotos de forma pública
app.use('/uploads', express.static(uploadsDir));

// ==========================================
// 2. CONEXIÓN A BASE DE DATOS (POOL)
// ==========================================
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'incidencias_escolares',
  port: process.env.DB_PORT || 4000,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // 👇 AGREGA ESTA LÍNEA DE AQUÍ ABAJO:
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  }
});

// Probar conexión a la base de datos
db.getConnection()
  .then(conn => {
    console.log('✅ Conectado exitosamente a la base de datos MySQL');
    conn.release();
  })
  .catch(err => {
    console.error('❌ Error de conexión a la base de datos:', err.message);
  });

// ==========================================
// 3. CONFIGURACIÓN DE MULTER (IMÁGENES)
// ==========================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    // Genera un nombre único: evidencia-1698234823-12345.jpg
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `evidencia-${uniqueSuffix}${ext}`);
  }
});

// Filtro corregido: acepta jpeg, jpg, png, webp, gif y sin fallar por mayúsculas
const fileFilter = (req, file, cb) => {
  const allowedExtensions = /jpeg|jpg|png|webp|gif/;
  const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
  const mime = file.mimetype.toLowerCase();

  // Comprueba si la extensión o el mimetype coinciden con una imagen válida
  if (allowedExtensions.test(ext) || allowedExtensions.test(mime)) {
    cb(null, true);
  } else {
    cb(new Error('Solo se permiten archivos de imagen (jpg, jpeg, png, webp, gif)'), false);
  }
};

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // Límite de 10 MB por foto
  fileFilter
});

// ==========================================
// 4. RUTAS DEL API
// ==========================================

// Ruta raíz de prueba
app.get('/', (req, res) => {
  res.send('🚀 Servidor de Incidencias Escolares activo');
});

// REGISTRO DE USUARIOS
app.post('/registro', async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }

    // Normalizar el rol (Usuario o Admin)
    const rolNormalizado = rol && rol.toLowerCase() === 'admin' ? 'Admin' : 'Usuario';

    const [result] = await db.query(
      'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)',
      [nombre, email, password, rolNormalizado]
    );

    res.status(201).json({
      mensaje: 'Usuario registrado exitosamente',
      usuarioId: result.insertId
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'El correo electrónico ya está registrado' });
    }
    console.error('Error en /registro:', error);
    res.status(500).json({ error: error.message });
  }
});

// LOGIN DE USUARIOS
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await db.query(
      'SELECT id, nombre, email, password, rol FROM usuarios WHERE email = ?',
      [email]
    );

    if (rows.length === 0 || rows[0].password !== password) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const usuario = rows[0];
    res.json({
      mensaje: 'Inicio de sesión exitoso',
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol
      }
    });
  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ error: error.message });
  }
});

// OBTENER CATEGORÍAS
app.get('/categorias', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM categorias');
    res.json(rows);
  } catch (error) {
    console.error('Error en /categorias:', error);
    res.status(500).json({ error: error.message });
  }
});

// CREAR INCIDENCIA (Acepta foto de evidencia)
// CREAR INCIDENCIA (Adaptado para la columna 'imagen')
app.post('/incidencias', (req, res, next) => {
  // Acepta la foto tanto si la app la envía como 'imagen' o como 'evidencia'
  upload.fields([{ name: 'imagen', maxCount: 1 }, { name: 'evidencia', maxCount: 1 }])(req, res, (err) => {
    if (err) return next(err);
    next();
  });
}, async (req, res) => {
  try {
    const { usuario_id, categoria_id, descripcion } = req.body;

    if (!descripcion) {
      return res.status(400).json({ error: 'La descripción es obligatoria' });
    }

    // Detectar el archivo subido (ya sea que vino como req.files.imagen o req.files.evidencia)
    let rutaImagen = null;
    if (req.files) {
      const file = req.files['imagen']?.[0] || req.files['evidencia']?.[0];
      if (file) {
        rutaImagen = `/uploads/${file.filename}`;
      }
    }

    // Si categoría viene como texto ("Informática"), obtenemos su ID numérico
    let finalCategoriaId = categoria_id;
    if (isNaN(categoria_id)) {
      const [catRows] = await db.query(
        'SELECT id FROM categorias WHERE nombre = ? LIMIT 1',
        [categoria_id]
      );
      if (catRows.length > 0) {
        finalCategoriaId = catRows[0].id;
      }
    }

    // INSERT usando tu columna 'imagen'
    const [result] = await db.query(
      `INSERT INTO incidencias (usuario_id, categoria_id, descripcion, imagen, estado) 
       VALUES (?, ?, ?, ?, 'Pendiente')`,
      [usuario_id || null, finalCategoriaId || null, descripcion, rutaImagen]
    );

    res.status(201).json({
      mensaje: 'Incidencia reportada con éxito',
      id: result.insertId,
      imagen: rutaImagen
    });
  } catch (error) {
    console.error('Error al registrar incidencia:', error);
    res.status(500).json({ error: error.message });
  }
});

// LISTAR INCIDENCIAS
app.get('/incidencias', async (req, res) => {
  try {
    const query = `
      SELECT i.*, u.nombre AS usuario_nombre, c.nombre AS categoria_nombre 
      FROM incidencias i
      LEFT JOIN usuarios u ON i.usuario_id = u.id
      LEFT JOIN categorias c ON i.categoria_id = c.id
      ORDER BY i.fecha DESC
    `;
    const [rows] = await db.query(query);
    res.json(rows);
  } catch (error) {
    console.error('Error en GET /incidencias:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// 5. MANEJADOR GLOBAL DE ERRORES (MULTER / 500)
// ==========================================
app.use((err, req, res, next) => {
  // Manejo de errores lanzados por Multer o fileFilter
  if (err instanceof multer.MulterError || err.message.includes('Solo se permiten')) {
    return res.status(400).json({ error: err.message });
  }

  console.error('Error no controlado:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor ejecutándose en el puerto ${PORT}`);
});
