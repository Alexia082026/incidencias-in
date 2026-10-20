const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "mi_clave_secreta_jwt";

app.use(cors());
app.use(express.json());

// Crear carpeta uploads si no existe
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use("/uploads", express.static(uploadsDir));

// ==========================================
// CONEXIÓN A BASE DE DATOS (TiDB / Render / Local)
// ==========================================
const conexion = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: process.env.DB_PORT || 4000,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "incidencias_escolares",
  waitForConnections: true,
  connectionLimit: 10,
  // SSL obligatorio para TiDB Cloud
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  }
});

// Probar conexión
conexion.getConnection((err, conn) => {
  if (err) {
    console.error("❌ Error conectando a la BD:", err.message);
  } else {
    console.log("✅ Conectado exitosamente a MySQL/TiDB");
    conn.release();
  }
});

// ==========================================
// CONFIGURACIÓN DE MULTER (FOTOS)
// ==========================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + ext);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp|gif/;
    const ext = path.extname(file.originalname).toLowerCase().replace(".", "");
    const mime = file.mimetype.toLowerCase();
    if (allowed.test(ext) || allowed.test(mime)) {
      cb(null, true);
    } else {
      cb(new Error("Solo se permiten archivos de imagen (jpg, jpeg, png, webp, gif)"), false);
    }
  }
});

// Middleware para verificar JWT
const verificarToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(403).json({ mensaje: "Token no proporcionado" });
  }

  const token = authHeader.replace("Bearer ", "").trim();
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ mensaje: "Token inválido o expirado" });
    }
    req.usuario = decoded;
    next();
  });
};

// ==========================================
// RUTAS DE LA GUÍA 9
// ==========================================

app.get("/", (req, res) => {
  res.send("🚀 Servidor de Incidencias Guía 9 Activo");
});

// REGISTRO
app.post("/registro", async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)";

    conexion.query(sql, [nombre, email, hash, rol || "Usuario"], (error) => {
      if (error) return res.status(500).json({ mensaje: error.message });
      res.json({ mensaje: "Usuario registrado con éxito" });
    });
  } catch (e) {
    res.status(500).json({ mensaje: e.message });
  }
});

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM usuarios WHERE email = ?";

  conexion.query(sql, [email], async (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }

    const usuario = resultado[0];
    const passwordValida = await bcrypt.compare(password, usuario.password);
    if (!passwordValida) {
      return res.status(401).json({ mensaje: "Contraseña incorrecta" });
    }

    const token = jwt.sign({ id: usuario.id, rol: usuario.rol }, SECRET_KEY, {
      expiresIn: "8h"
    });

    res.json({
      mensaje: "Inicio de sesión exitoso",
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol
      }
    });
  });
});

// PERFIL DE USUARIO
app.get("/perfil", verificarToken, (req, res) => {
  const usuarioId = req.usuario.id;
  const sql = "SELECT id, nombre, email, rol FROM usuarios WHERE id = ?";

  conexion.query(sql, [usuarioId], (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }
    res.json(resultado[0]);
  });
});

// CATEGORÍAS
app.get("/categorias", (req, res) => {
  conexion.query("SELECT * FROM categorias", (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json(resultado);
  });
});

// LISTADO DE INCIDENCIAS
app.get("/incidencias", (req, res) => {
  const { buscar, categoria_id, estado } = req.query;

  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen, c.nombre AS categoria
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    WHERE 1=1
  `;
  const parametros = [];

  if (buscar) {
    sql += " AND i.descripcion LIKE ?";
    parametros.push(`%${buscar}%`);
  }
  if (categoria_id) {
    sql += " AND i.categoria_id = ?";
    parametros.push(categoria_id);
  }
  if (estado) {
    sql += " AND i.estado = ?";
    parametros.push(estado);
  }

  sql += " ORDER BY i.fecha DESC";

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json(resultado);
  });
});

// EXPORTAR PARA PDF
app.get("/incidencias/exportar", (req, res) => {
  const { fecha_inicio, fecha_fin } = req.query;

  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, c.nombre AS categoria
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    WHERE 1=1
  `;
  const parametros = [];

  if (fecha_inicio && fecha_fin) {
    sql += " AND DATE(i.fecha) BETWEEN ? AND ?";
    parametros.push(fecha_inicio, fecha_fin);
  }

  sql += " ORDER BY i.fecha DESC";

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json(resultado);
  });
});

// RESUELTAS
app.get("/incidencias/resueltas", (req, res) => {
  const sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen, c.nombre AS categoria
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    WHERE i.estado = 'Resuelto'
    ORDER BY i.fecha DESC
  `;
  conexion.query(sql, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json(resultado);
  });
});

// REGISTRAR INCIDENCIA
app.post("/incidencias", upload.single("imagen"), (req, res) => {
  const { categoria_id, descripcion, usuario_id } = req.body;
  const imagen = req.file ? req.file.filename : null;
  const sql = "INSERT INTO incidencias (usuario_id, categoria_id, descripcion, imagen) VALUES (?, ?, ?, ?)";

  conexion.query(sql, [usuario_id || null, categoria_id, descripcion, imagen], (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    // Usamos 200 para que la app no muestre 'código 201'
    res.status(200).json({
      mensaje: "Incidencia registrada correctamente",
      id: resultado.insertId
    });
  });
});

// CAMBIAR ESTADO
app.put("/incidencias/:id/estado", verificarToken, (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;
  const sql = "UPDATE incidencias SET estado = ? WHERE id = ?";

  conexion.query(sql, [estado, id], (error) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json({ mensaje: "Estado actualizado correctamente" });
  });
});

// ELIMINAR INCIDENCIA (Solo Admin)
app.delete("/incidencias/:id", verificarToken, (req, res) => {
  const { id } = req.params;

  if (req.usuario.rol !== "Admin") {
    return res.status(403).json({ mensaje: "Acceso denegado: Requiere rol Admin" });
  }

  const sql = "DELETE FROM incidencias WHERE id = ?";

  conexion.query(sql, [id], (error) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json({ mensaje: "Incidencia eliminada correctamente" });
  });
});

// ESTADÍSTICAS
app.get("/estadisticas/categorias", (req, res) => {
  const sql = `
    SELECT c.nombre AS categoria, COUNT(i.id) AS total
    FROM categorias c
    LEFT JOIN incidencias i ON c.id = i.categoria_id
    GROUP BY c.id, c.nombre
  `;
  conexion.query(sql, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json(resultado);
  });
});

app.get("/estadisticas/estados", (req, res) => {
  const sql = `
    SELECT estado, COUNT(id) AS total
    FROM incidencias
    GROUP BY estado
  `;
  conexion.query(sql, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: error.message });
    res.json(resultado);
  });
});

// Manejador de errores
app.use((err, req, res, next) => {
  res.status(400).json({ mensaje: err.message });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Servidor ejecutándose en el puerto ${PORT}`);
});
