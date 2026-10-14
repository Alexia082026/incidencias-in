// Instalación:
//   npm init -y
//   npm install express mysql2 cors multer bcryptjs jsonwebtoken
// Ejecución:
//   node server.js

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Carpeta de almacenamiento
const carpetaUploads = path.join(__dirname, "uploads");
if (!fs.existsSync(carpetaUploads)) {
  fs.mkdirSync(carpetaUploads, { recursive: true });
}
app.use("/uploads", express.static(carpetaUploads));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.SECRET_KEY || "clave_secreta_inframen_2026";
const ESTADOS_VALIDOS = ["Pendiente", "En revisión", "En proceso", "Resuelto"];

// ---------------- BASE DE DATOS (POOL DE CONEXIONES) ----------------
// Usar createPool evita caídas por timeout en TiDB / Render
const configDB = {
  host: process.env.DB_HOST || "localhost",
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "sistema_incidencias",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

// Solo activar SSL si estamos apuntando a un host remoto
if (process.env.DB_HOST && process.env.DB_HOST !== "localhost") {
  configDB.ssl = { rejectUnauthorized: false };
}

const conexion = mysql.createPool(configDB);

conexion.getConnection((err, conn) => {
  if (err) {
    console.error("Error al conectar con el Pool de MySQL:", err.message);
    return;
  }
  console.log("Conectado exitosamente al Pool de MySQL");
  conn.release();
});

// ---------------- CONFIGURACIÓN MULTER ----------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, carpetaUploads),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  },
});

// Validar que solo suban imágenes y fijar límite de tamaño (5MB)
const fileFilter = (req, file, cb) => {
  const permitidos = /jpeg|jpg|png|webp|gif/;
  const esMimeValido = permitidos.test(file.mimetype);
  const esExtValida = permitidos.test(path.extname(file.originalname).toLowerCase());

  if (esMimeValido && esExtValida) {
    cb(null, true);
  } else {
    cb(new Error("Solo se permiten archivos de imagen (jpg, png, webp, gif)"));
  }
};

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter,
});

// ---------------- MIDDLEWARE JWT ----------------
const verificarToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(403).json({ mensaje: "Token requerido" });
  }

  try {
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : authHeader;
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ mensaje: "Token inválido o expirado" });
  }
};

app.get("/", (req, res) => {
  res.send("API Sistema de Incidencias");
});

// ---------------- AUTENTICACIÓN ----------------
app.post("/registro", async (req, res) => {
  const { nombre, email, password } = req.body;

  if (!nombre || !email || !password) {
    return res.status(400).json({ mensaje: "Todos los campos son obligatorios" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, 'Usuario')";

    conexion.query(sql, [nombre, email, hashedPassword], (error) => {
      if (error) {
        if (error.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ mensaje: "Ese correo ya está registrado" });
        }
        return res.status(500).json({ mensaje: "Error al registrar el usuario" });
      }
      res.json({ mensaje: "Usuario registrado correctamente" });
    });
  } catch (e) {
    res.status(500).json({ mensaje: "Error al procesar el registro" });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ mensaje: "Correo y contraseña son obligatorios" });
  }

  conexion.query("SELECT * FROM usuarios WHERE email = ?", [email], async (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error en la consulta" });
    if (resultado.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado" });

    const usuario = resultado[0];
    const passwordValida = await bcrypt.compare(password, usuario.password);

    if (!passwordValida) {
      return res.status(401).json({ mensaje: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      mensaje: "Inicio de sesión exitoso",
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol,
      },
    });
  });
});

// ---------------- CATEGORÍAS E INCIDENCIAS ----------------
app.get("/categorias", (req, res) => {
  conexion.query("SELECT * FROM categorias", (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al obtener categorías" });
    res.json(resultado);
  });
});

app.get("/incidencias", verificarToken, (req, res) => {
  const esAdmin = req.usuario.rol === "Admin";
  const { buscar, categoria_id, estado } = req.query;

  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen, c.nombre AS categoria, u.nombre AS usuario
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    LEFT JOIN usuarios u ON i.usuario_id = u.id
    WHERE 1=1
  `;
  const parametros = [];

  if (!esAdmin) {
    sql += " AND i.usuario_id = ?";
    parametros.push(req.usuario.id);
  }
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
    if (error) return res.status(500).json({ mensaje: "Error al obtener incidencias" });
    res.json(resultado);
  });
});

app.get("/incidencias/exportar", verificarToken, (req, res) => {
  const esAdmin = req.usuario.rol === "Admin";
  const { fecha_inicio, fecha_fin } = req.query;

  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, c.nombre AS categoria
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    WHERE 1=1
  `;
  const parametros = [];

  if (!esAdmin) {
    sql += " AND i.usuario_id = ?";
    parametros.push(req.usuario.id);
  }
  if (fecha_inicio && fecha_fin) {
    sql += " AND DATE(i.fecha) BETWEEN ? AND ?";
    parametros.push(fecha_inicio, fecha_fin);
  }

  sql += " ORDER BY i.fecha DESC";

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al exportar incidencias" });
    res.json(resultado);
  });
});

app.get("/incidencias/resueltas", verificarToken, (req, res) => {
  const esAdmin = req.usuario.rol === "Admin";
  const sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen, c.nombre AS categoria, u.nombre AS usuario
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    LEFT JOIN usuarios u ON i.usuario_id = u.id
    WHERE i.estado = 'Resuelto' ${esAdmin ? "" : "AND i.usuario_id = ?"}
    ORDER BY i.fecha DESC
  `;
  const parametros = esAdmin ? [] : [req.usuario.id];

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al obtener incidencias resueltas" });
    res.json(resultado);
  });
});

app.post("/incidencias", verificarToken, upload.single("imagen"), (req, res) => {
  const { categoria_id, descripcion } = req.body;
  const imagen = req.file ? req.file.filename : null;
  const usuario_id = req.usuario.id;

  if (!categoria_id || !descripcion || descripcion.trim() === "") {
    return res.status(400).json({ mensaje: "Categoría y descripción son obligatorias" });
  }

  const sql = "INSERT INTO incidencias (usuario_id, categoria_id, descripcion, imagen) VALUES (?, ?, ?, ?)";
  conexion.query(sql, [usuario_id, categoria_id, descripcion, imagen], (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al registrar incidencia" });
    res.json({
      mensaje: "Incidencia registrada correctamente",
      id: resultado.insertId,
    });
  });
});

app.put("/incidencias/:id/estado", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res.status(403).json({ mensaje: "Acceso denegado. Se requieren permisos de Administrador." });
  }

  const { id } = req.params;
  const { estado } = req.body;

  if (!estado || !ESTADOS_VALIDOS.includes(estado)) {
    return res.status(400).json({
      mensaje: `Estado no válido. Opciones: ${ESTADOS_VALIDOS.join(", ")}`,
    });
  }

  conexion.query("UPDATE incidencias SET estado = ? WHERE id = ?", [estado, id], (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al actualizar el estado" });
    if (resultado.affectedRows === 0) return res.status(404).json({ mensaje: "Incidencia no encontrada" });
    res.json({ mensaje: "Estado actualizado correctamente" });
  });
});

// Eliminar incidencia y su imagen física del disco
app.delete("/incidencias/:id", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res.status(403).json({ mensaje: "Acceso denegado. Se requieren permisos de Administrador." });
  }

  const { id } = req.params;

  conexion.query("SELECT imagen FROM incidencias WHERE id = ?", [id], (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al consultar la incidencia" });
    if (resultado.length === 0) return res.status(404).json({ mensaje: "Incidencia no encontrada" });

    const imagen = resultado[0].imagen;

    conexion.query("DELETE FROM incidencias WHERE id = ?", [id], (errDelete) => {
      if (errDelete) return res.status(500).json({ mensaje: "Error al eliminar la incidencia" });

      if (imagen) {
        const rutaArchivo = path.join(carpetaUploads, imagen);
        if (fs.existsSync(rutaArchivo)) {
          fs.unlink(rutaArchivo, () => {});
        }
      }

      res.json({ mensaje: "Incidencia eliminada correctamente" });
    });
  });
});

// ---------------- ESTADÍSTICAS Y PERFIL ----------------
app.get("/estadisticas/categorias", verificarToken, (req, res) => {
  const esAdmin = req.usuario.rol === "Admin";
  const sql = `
    SELECT c.nombre AS categoria, COUNT(i.id) AS total
    FROM categorias c
    LEFT JOIN incidencias i ON c.id = i.categoria_id ${esAdmin ? "" : "AND i.usuario_id = ?"}
    GROUP BY c.id, c.nombre
  `;
  const parametros = esAdmin ? [] : [req.usuario.id];

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al obtener estadísticas" });
    res.json(resultado);
  });
});

app.get("/estadisticas/estados", verificarToken, (req, res) => {
  const esAdmin = req.usuario.rol === "Admin";
  const sql = `
    SELECT estado, COUNT(id) AS total
    FROM incidencias
    ${esAdmin ? "" : "WHERE usuario_id = ?"}
    GROUP BY estado
  `;
  const parametros = esAdmin ? [] : [req.usuario.id];

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al obtener estadísticas" });
    res.json(resultado);
  });
});

app.get("/perfil", verificarToken, (req, res) => {
  conexion.query("SELECT id, nombre, email, rol, fecha_registro FROM usuarios WHERE id = ?", [req.usuario.id], (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al obtener perfil" });
    if (resultado.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado" });
    res.json(resultado[0]);
  });
});

// ---------------- GESTIÓN DE USUARIOS ----------------
app.get("/usuarios", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res.status(403).json({ mensaje: "Acceso denegado." });
  }

  conexion.query("SELECT id, nombre, email, rol, fecha_registro FROM usuarios ORDER BY fecha_registro DESC", (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al obtener usuarios" });
    res.json(resultado);
  });
});

app.delete("/usuarios/:id", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res.status(403).json({ mensaje: "Acceso denegado." });
  }

  const { id } = req.params;

  conexion.query("SELECT rol FROM usuarios WHERE id = ?", [id], (error, resultado) => {
    if (error) return res.status(500).json({ mensaje: "Error al verificar usuario" });
    if (resultado.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado" });
    if (resultado[0].rol === "Admin") {
      return res.status(403).json({ mensaje: "No se puede eliminar una cuenta de Administrador" });
    }

    conexion.query("DELETE FROM usuarios WHERE id = ?", [id], (error2) => {
      if (error2) {
        if (error2.code === "ER_ROW_IS_REFERENCED_2") {
          return res.status(400).json({ mensaje: "No se puede eliminar el usuario porque tiene incidencias asociadas." });
        }
        return res.status(500).json({ mensaje: "Error al eliminar el usuario" });
      }
      res.json({ mensaje: "Usuario eliminado correctamente" });
    });
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor activo en el puerto ${PORT}`);
});
