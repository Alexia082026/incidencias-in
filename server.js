// Instalación (en la carpeta del proyecto):
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

// Asegura que exista la carpeta de imágenes (multer falla si no existe)
const carpetaUploads = path.join(__dirname, "uploads");
if (!fs.existsSync(carpetaUploads)) {
  fs.mkdirSync(carpetaUploads, { recursive: true });
}

// Servir la carpeta de imágenes de forma pública/dinámica
app.use("/uploads", express.static(carpetaUploads));

// Puerto: usa el de la nube (Render lo inyecta) o 3000 en local
const PORT = process.env.PORT || 3000;

// Clave JWT: usa la variable de entorno en producción; si no existe
// (desarrollo local), cae en la clave de pruebas
const JWT_SECRET = process.env.SECRET_KEY || "clave_secreta_inframen_2026";

// Estados permitidos para una incidencia (deben coincidir con la app y la BD)
const ESTADOS_VALIDOS = ["Pendiente", "En revisión", "En proceso", "Resuelto"];

// Conexión a MySQL: usa variables de entorno si existen (Render + TiDB
// Cloud); si no (desarrollo local con XAMPP), usa los valores por defecto.
// DB_HOST presente = estamos en la nube => se activa SSL.
const conexion = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { 
      rejectUnauthorized: false
    }
});

conexion.connect((error) => {
  if (error) {
    console.error("Error al conectar con MySQL:", error.message);
    return;
  }
  console.log("Conectado a MySQL");
});

// Configuración de almacenamiento para Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, carpetaUploads);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });

// Middleware para verificar el token JWT en rutas protegidas
const verificarToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ mensaje: "Token requerido" });
  }

  try {
    const bearer = token.split(" ")[1] || token;
    const decoded = jwt.verify(bearer, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ mensaje: "Token inválido o expirado" });
  }
};

// ---------------- AUTENTICACIÓN ----------------

// Registro de usuario
// El rol SIEMPRE es "Usuario": los administradores se crean directamente
// en la base de datos (UPDATE usuarios SET rol = 'Admin' WHERE ...).
app.post("/registro", async (req, res) => {
  const { nombre, email, password } = req.body;

  if (!nombre || !email || !password) {
    return res
      .status(400)
      .json({ mensaje: "Todos los campos son obligatorios" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql =
      "INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)";

    conexion.query(
      sql,
      [nombre, email, hashedPassword, "Usuario"],
      (error, resultado) => {
        if (error) {
          console.error(error);
          if (error.code === "ER_DUP_ENTRY") {
            return res
              .status(409)
              .json({ mensaje: "Ese correo ya está registrado" });
          }
          return res.status(500).json({ mensaje: "Error al registrar el usuario" });
        }
        res.json({ mensaje: "Usuario registrado correctamente" });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ mensaje: "Error al procesar el registro" });
  }
});

// Inicio de sesión
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ mensaje: "Correo y contraseña son obligatorios" });
  }

  const sql = "SELECT * FROM usuarios WHERE email = ?";

  conexion.query(sql, [email], async (error, resultado) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al iniciar sesión" });
    }
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }

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

// Obtener categorías
app.get("/categorias", (req, res) => {
  conexion.query("SELECT * FROM categorias", (error, resultado) => {
    if (error) {
      return res.status(500).json({ mensaje: "Error al obtener categorías" });
    }
    res.json(resultado);
  });
});

// Obtener incidencias con filtros dinámicos y búsqueda
// (un Usuario ve solo las suyas; un Admin las ve todas; ambos pueden filtrar)
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
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al obtener incidencias" });
    }
    res.json(resultado);
  });
});

// Obtener incidencias por rango de fechas, para exportar a PDF
// (un Usuario exporta solo las suyas; un Admin exporta todas)
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
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al exportar incidencias" });
    }
    res.json(resultado);
  });
});

// Obtener únicamente incidencias RESUELTAS (un Usuario ve solo las suyas; un Admin las ve todas)
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
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al obtener incidencias resueltas" });
    }
    res.json(resultado);
  });
});

// Registrar incidencia (requiere sesión iniciada; queda ligada al usuario)
app.post("/incidencias", verificarToken, upload.single("imagen"), (req, res) => {
  const { categoria_id, descripcion } = req.body;
  const imagen = req.file ? req.file.filename : null;
  const usuario_id = req.usuario.id;

  if (!categoria_id || !descripcion || descripcion.trim() === "") {
    return res
      .status(400)
      .json({ mensaje: "Categoría y descripción son obligatorias" });
  }

  const sql =
    "INSERT INTO incidencias (usuario_id, categoria_id, descripcion, imagen) VALUES (?, ?, ?, ?)";

  conexion.query(
    sql,
    [usuario_id, categoria_id, descripcion, imagen],
    (error, resultado) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ mensaje: "Error al registrar incidencia" });
      }
      res.json({
        mensaje: "Incidencia registrada correctamente",
        id: resultado.insertId,
      });
    }
  );
});

// Cambiar estado de una incidencia (solo Admin)
app.put("/incidencias/:id/estado", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res
      .status(403)
      .json({ mensaje: "Acceso denegado. Se requieren permisos de Administrador." });
  }

  const { id } = req.params;
  const { estado } = req.body;

  if (!estado) {
    return res.status(400).json({ mensaje: "El estado es obligatorio" });
  }
  if (!ESTADOS_VALIDOS.includes(estado)) {
    return res.status(400).json({
      mensaje: `Estado no válido. Usa: ${ESTADOS_VALIDOS.join(", ")}`,
    });
  }

  const sql = "UPDATE incidencias SET estado = ? WHERE id = ?";

  conexion.query(sql, [estado, id], (error, resultado) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al actualizar el estado" });
    }
    if (resultado.affectedRows === 0) {
      return res.status(404).json({ mensaje: "Incidencia no encontrada" });
    }
    res.json({ mensaje: "Estado actualizado correctamente" });
  });
});

// Eliminar una incidencia por su ID (solo Admin)
app.delete("/incidencias/:id", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res
      .status(403)
      .json({ mensaje: "Acceso denegado. Se requieren permisos de Administrador." });
  }

  const { id } = req.params;
  const sql = "DELETE FROM incidencias WHERE id = ?";

  conexion.query(sql, [id], (error, resultado) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al eliminar la incidencia" });
    }
    if (resultado.affectedRows === 0) {
      return res.status(404).json({ mensaje: "Incidencia no encontrada" });
    }
    res.json({ mensaje: "Incidencia eliminada correctamente" });
  });
});

// ---------------- ESTADÍSTICAS ----------------

// Estadísticas agrupadas por categoría (un Usuario ve solo las suyas; un Admin las ve todas)
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
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al obtener estadísticas" });
    }
    res.json(resultado);
  });
});

// Estadísticas agrupadas por estado (un Usuario ve solo las suyas; un Admin las ve todas)
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
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al obtener estadísticas" });
    }
    res.json(resultado);
  });
});

// Obtener el perfil del usuario autenticado (a partir de su propio token)
app.get("/perfil", verificarToken, (req, res) => {
  const usuarioId = req.usuario.id;
  const sql =
    "SELECT id, nombre, email, rol, fecha_registro FROM usuarios WHERE id = ?";

  conexion.query(sql, [usuarioId], (error, resultado) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al obtener el perfil" });
    }
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }
    res.json(resultado[0]);
  });
});

// ---------------- GESTIÓN DE USUARIOS (solo Admin) ----------------

// Obtener todos los usuarios (incluye cuentas Admin; el frontend decide qué mostrar)
app.get("/usuarios", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res
      .status(403)
      .json({ mensaje: "Acceso denegado. Se requieren permisos de Administrador." });
  }

  const sql =
    "SELECT id, nombre, email, rol, fecha_registro FROM usuarios ORDER BY fecha_registro DESC";

  conexion.query(sql, (error, resultado) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al obtener usuarios" });
    }
    res.json(resultado);
  });
});

// Eliminar un usuario por su ID (solo Admin; no se puede eliminar una cuenta Admin)
app.delete("/usuarios/:id", verificarToken, (req, res) => {
  if (req.usuario.rol !== "Admin") {
    return res
      .status(403)
      .json({ mensaje: "Acceso denegado. Se requieren permisos de Administrador." });
  }

  const { id } = req.params;

  const sqlVerificar = "SELECT rol FROM usuarios WHERE id = ?";
  conexion.query(sqlVerificar, [id], (error, resultado) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ mensaje: "Error al verificar el usuario" });
    }
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado" });
    }
    if (resultado[0].rol === "Admin") {
      return res
        .status(403)
        .json({ mensaje: "No se puede eliminar una cuenta de Administrador" });
    }

    const sql = "DELETE FROM usuarios WHERE id = ?";
    conexion.query(sql, [id], (error2) => {
      if (error2) {
        console.error(error2);
        return res.status(500).json({ mensaje: "Error al eliminar el usuario" });
      }
      res.json({ mensaje: "Usuario eliminado correctamente" });
    });
  });
});

// "0.0.0.0" permite conexiones tanto en red local (celular) como en la nube (Render)
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor activo en el puerto ${PORT}`);
});
