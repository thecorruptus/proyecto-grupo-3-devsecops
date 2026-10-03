const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const xss = require('xss');
const winston = require('winston');
const ipaddr = require('ipaddr.js');
const dns = require('dns').promises;

const app = express();

// A05: Mitigación de Security Misconfiguration
// Helmet configura cabeceras de seguridad HTTP y elimina 'X-Powered-By'
app.use(helmet());
app.use(express.json());

// A02: Clave secreta robusta (en producción se suministra por variables de entorno)
const JWT_SECRET = process.env.JWT_SECRET || "Clave_Ultra_Segura_CampusVirtual_2026_Entropia_Alta!";

// A09: Configuración de Logging centralizado y persistente con Winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'security-audit.log' })
  ]
});

// Inicialización de base de datos en memoria para pruebas
const db = new sqlite3.Database(':memory:');

db.serialize(async () => {
  db.run(`CREATE TABLE students (id INTEGER PRIMARY KEY, rut TEXT, name TEXT, grade REAL)`);
  db.run(`CREATE TABLE teachers (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)`);
  db.run(`CREATE TABLE exams (id INTEGER PRIMARY KEY, title TEXT, start_time INTEGER, end_time INTEGER)`);
  db.run(`CREATE TABLE forum_posts (id INTEGER PRIMARY KEY, author TEXT, content TEXT)`);

  // Semilla de alumnos
  db.run(`INSERT INTO students (rut, name, grade) VALUES ('12345678-5', 'Estudiante Prueba', 4.0)`);

  // A07: Contraseñas con hashing robusto (Bcrypt con sal aleatoria, costo 10)
  const saltRounds = 10;
  const secureHash = await bcrypt.hash('profesor123', saltRounds);
  db.run(`INSERT INTO teachers (email, password_hash) VALUES ('profesor@campus.cl', ?)`, [secureHash]);

  // Examen de prueba (con plazo de entrega finalizado hace 1 hora)
  const pastStart = Date.now() - 7200000;
  const pastEnd = Date.now() - 3600000;
  db.run(`INSERT INTO exams (id, title, start_time, end_time) VALUES (1, 'Examen Parcial Redes', ${pastStart}, ${pastEnd})`);
});

// Middleware de verificación de autenticación (A01 y A02)
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: "Acceso no autorizado: Token JWT requerido" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido o expirado" });
    }
    req.user = decodedUser;
    next();
  });
}

// Middleware de control de acceso por rol estricto (A01)
function requireRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== requiredRole) {
      logger.warn({
        event: 'UNAUTHORIZED_ROLE_ACCESS',
        user: req.user ? req.user.rut || req.user.email : 'anonimo',
        attemptedPath: req.path,
        requiredRole
      });
      return res.status(403).json({ error: "Permisos insuficientes para esta operación" });
    }
    next();
  };
}

// --- ENDPOINTS BLINDADOS ---

// A01: Solo administradores autenticados pueden modificar notas.
// El rol NO se toma de req.body, sino del token validado.
app.post('/api/grades/update', authenticateToken, requireRole('admin'), (req, res) => {
  const { studentId, grade } = req.body;

  if (typeof grade !== 'number' || grade < 1.0 || grade > 7.0) {
    return res.status(400).json({ error: "Calificación inválida (debe estar entre 1.0 y 7.0)" });
  }

  db.run(`UPDATE students SET grade = ? WHERE id = ?`, [grade, studentId], function(err) {
    if (err) return res.status(500).json({ error: "Error interno al actualizar calificación" });
    res.status(200).json({ message: "Calificación actualizada exitosamente" });
  });
});

// A02: Generación segura de tokens con tiempo de expiración corto (15 min)
app.post('/api/login/student', (req, res) => {
  const { rut } = req.body;
  if (!rut) return res.status(400).json({ error: "RUT requerido" });

  const token = jwt.sign({ rut, role: 'student' }, JWT_SECRET, { expiresIn: '15m' });
  res.status(200).json({ token });
});

// A03: Validación estricta por lista blanca / Regex y uso de Prepared Statements (?)
app.get('/api/students', (req, res) => {
  const { rut } = req.query;
  const rutRegex = /^[0-9]{7,8}-[0-9kK]{1}$/;

  if (!rut || !rutRegex.test(rut)) {
    return res.status(400).json({ error: "Formato de RUT inválido. Formato esperado: 12345678-9" });
  }

  db.all(`SELECT id, rut, name, grade FROM students WHERE rut = ?`, [rut], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error en la consulta" });
    res.status(200).json(rows);
  });
});

// A04 & A09: Lógica de negocio con control temporal en el servidor y logging
app.post('/api/exams/:id/submit', authenticateToken, (req, res) => {
  const examId = req.params.id;
  const currentTime = Date.now();

  db.get(`SELECT * FROM exams WHERE id = ?`, [examId], (err, exam) => {
    if (err || !exam) return res.status(404).json({ error: "Examen no encontrado" });

    if (currentTime > exam.end_time) {
      logger.warn({
        event: 'EXAM_SUBMISSION_EXPIRED',
        rut: req.user.rut,
        examId,
        submissionTime: new Date(currentTime).toISOString()
      });
      return res.status(400).json({ error: "El plazo reglamentario para responder este examen ha expirado" });
    }

    res.status(200).json({ message: "Examen enviado dentro del plazo reglamentario" });
  });
});

// A05: Manejo de ruta no encontrada en lugar de exponer /debug/config
app.get('/debug/config', (req, res) => {
  res.status(404).json({ error: "Endpoint deshabilitado en entornos productivos" });
});

// A07: Verificación con Bcrypt seguro
app.post('/api/login/teacher', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Credenciales incompletas" });

  db.get(`SELECT * FROM teachers WHERE email = ?`, [email], async (err, teacher) => {
    if (err || !teacher) return res.status(401).json({ error: "Credenciales inválidas" });

    const passwordMatch = await bcrypt.compare(password, teacher.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: "Credenciales inválidas" });

    const token = jwt.sign({ email: teacher.email, role: 'teacher' }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: "Autenticación docente exitosa", token });
  });
});

// A08: Sanitización de entradas contra XSS
app.post('/api/forum/posts', authenticateToken, (req, res) => {
  const { content } = req.body;
  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: "Contenido de publicación inválido" });
  }

  // Sanitización estricta: elimina etiquetas HTML y scripts maliciosos
  const cleanContent = xss(content, { whiteList: {}, stripIgnoreTag: true });

  db.run(`INSERT INTO forum_posts (author, content) VALUES (?, ?)`, [req.user.rut, cleanContent], function(err) {
    if (err) return res.status(500).json({ error: "Error al publicar comentario" });
    res.status(201).json({ message: "Comentario sanitizado y guardado con éxito", postId: this.lastID, content: cleanContent });
  });
});

// A09: Detección y registro de acceso prematuro a evaluaciones
app.get('/api/exams/:id/content', authenticateToken, (req, res) => {
  const examId = req.params.id;
  const currentTime = Date.now();

  db.get(`SELECT * FROM exams WHERE id = ?`, [examId], (err, exam) => {
    if (err || !exam) return res.status(404).json({ error: "Examen no encontrado" });

    if (currentTime < exam.start_time) {
      logger.warn({
        event: 'PREMATURE_EXAM_ACCESS_ATTEMPT',
        rut: req.user.rut,
        examId,
        attemptTime: new Date(currentTime).toISOString()
      });
      return res.status(403).json({ error: "La evaluación aún no inicia" });
    }

    res.status(200).json({ id: exam.id, title: exam.title });
  });
});

// A10: Prevención de SSRF con lista blanca y bloqueo de IPs privadas/locales
app.post('/api/exams/import-external', authenticateToken, requireRole('teacher'), async (req, res) => {
  const { url } = req.body;
  try {
    const targetUrl = new URL(url);

    // Solo permitir protocolo HTTPS
    if (targetUrl.protocol !== 'https:') {
      return res.status(400).json({ error: "Solo se permite el protocolo HTTPS" });
    }

    // Lista blanca estricta de dominios
    const allowedHosts = ['cdn.campusvirtual.cl', 'evaluaciones.inacap.cl'];
    if (!allowedHosts.includes(targetUrl.hostname)) {
      return res.status(403).json({ error: "Dominio no autorizado en la lista blanca" });
    }

    // Resolución DNS para evitar resolución hacia redes privadas (RFC 1918 / Loopback / Cloud Metadata)
    const addresses = await dns.resolve4(targetUrl.hostname);
    for (const ip of addresses) {
      const parsedIp = ipaddr.parse(ip);
      if (parsedIp.range() !== 'unicast') {
        return res.status(403).json({ error: "La IP resuelta pertenece a un rango restringido o privado" });
      }
    }

    res.status(200).json({ message: "URL validada exitosamente bajo política SSRF" });
  } catch (error) {
    res.status(400).json({ error: "URL inválida o no alcanzable" });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`[CampusVirtual API Blindada] Servidor seguro ejecutándose en http://localhost:${PORT}`);
});