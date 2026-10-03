const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const http = require('http');

const app = express();
app.use(express.json());

// A05: Exposición deliberada de Stack Traces y headers de Express
app.set('x-powered-by', true);

// A02: Secreto JWT trivial y predecible sin caducidad
const INSECURE_JWT_SECRET = "secret123";

// Base de datos SQLite en memoria para pruebas
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run(`CREATE TABLE students (id INTEGER PRIMARY KEY, rut TEXT, name TEXT, grade REAL)`);
  db.run(`CREATE TABLE teachers (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT)`);
  db.run(`CREATE TABLE exams (id INTEGER PRIMARY KEY, title TEXT, start_time INTEGER, end_time INTEGER)`);
  db.run(`CREATE TABLE forum_posts (id INTEGER PRIMARY KEY, author TEXT, content TEXT)`);

  // Semilla de datos iniciales
  db.run(`INSERT INTO students (rut, name, grade) VALUES ('12345678-5', 'Estudiante Prueba', 3.5)`);
  
  // A07: Contraseñas de profesores almacenadas con hash MD5 sin sal (salt)
  const md5Hash = crypto.createHash('md5').update('profesor123').digest('hex');
  db.run(`INSERT INTO teachers (email, password_hash) VALUES ('profesor@campus.cl', '${md5Hash}')`);

  // Examen configurado con plazo ya vencido
  const pastStart = Date.now() - 7200000; // Hace 2 horas
  const pastEnd = Date.now() - 3600000;   // Hace 1 hora
  db.run(`INSERT INTO exams (id, title, start_time, end_time) VALUES (1, 'Examen Parcial Redes', ${pastStart}, ${pastEnd})`);
});

// A01: Escalada de privilegios (Broken Access Control)
// Confía en el parámetro 'role' que envía el cliente en el JSON para modificar notas
app.post('/api/grades/update', (req, res) => {
  const { studentId, grade, role } = req.body;
  
  if (role === 'admin') {
    db.run(`UPDATE students SET grade = ? WHERE id = ?`, [grade, studentId], function(err) {
      if (err) return res.status(500).json({ error: err.message, stack: err.stack });
      return res.status(200).json({ message: "Nota modificada exitosamente por rol admin" });
    });
  } else {
    return res.status(403).json({ error: "No autorizado para modificar notas" });
  }
});

// A02: Emisión de token JWT inseguro
app.post('/api/login/student', (req, res) => {
  const { rut } = req.body;
  // Sin parámetro expiresIn: el token dura para siempre
  const token = jwt.sign({ rut, role: 'student' }, INSECURE_JWT_SECRET);
  res.json({ token });
});

// A03: Inyección SQL clásica directa por parámetro RUT
app.get('/api/students', (req, res) => {
  const rut = req.query.rut;
  // Concatenación directa insegura
  const query = "SELECT * FROM students WHERE rut = '" + rut + "'";
  
  db.all(query, (err, rows) => {
    // A05: Devuelve el error y la traza si la consulta falla
    if (err) return res.status(500).json({ error: err.message, queryExecuted: query });
    res.json(rows);
  });
});

// A04: Fallo de diseño en lógica de tiempo
// No valida si el tiempo actual superó end_time
app.post('/api/exams/:id/submit', (req, res) => {
  const { answers } = req.body;
  res.status(200).json({ 
    message: "Respuestas aceptadas correctamente (sin validación de horario límite)",
    receivedAnswers: answers 
  });
});

// A05: Exposición de configuración, variables de entorno y claves en texto plano
app.get('/debug/config', (req, res) => {
  res.status(200).json({
    environment: "production_insecure",
    db_type: "sqlite_in_memory",
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    jwt_secret_internal: INSECURE_JWT_SECRET
  });
});

// A07: Login docente usando MD5 sin sal
app.post('/api/login/teacher', (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash('md5').update(password || '').digest('hex');
  
  db.get(`SELECT * FROM teachers WHERE email = ? AND password_hash = ?`, [email, hash], (err, user) => {
    if (err || !user) return res.status(401).json({ error: "Credenciales inválidas" });
    const token = jwt.sign({ email: user.email, role: 'teacher' }, INSECURE_JWT_SECRET);
    res.json({ message: "Login docente correcto", token });
  });
});

// A08: Inserción directa en foros sin sanitizar (XSS Almacenado)
app.post('/api/forum/posts', (req, res) => {
  const { author, content } = req.body;
  db.run(`INSERT INTO forum_posts (author, content) VALUES (?, ?)`, [author, content], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ message: "Comentario publicado", postId: this.lastID, content });
  });
});

// A09: Ausencia total de logging ante accesos prematuros
app.get('/api/exams/:id/content', (req, res) => {
  // Retorna datos sin escribir registros en log ante aperturas no permitidas
  res.status(200).json({ message: "Examen retornado sin registrar traza de auditoría" });
});

// A10: SSRF - Importación de contenido desde cualquier URL sin restricción
app.post('/api/exams/import-external', (req, res) => {
  const { url } = req.body;
  
  try {
    http.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => { data += chunk; });
      response.on('end', () => {
        res.status(200).json({ message: "Contenido externo importado", dataPreview: data.substring(0, 100) });
      });
    }).on('error', (err) => {
      res.status(500).json({ error: "Error al consultar la URL", details: err.message });
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`[CampusVirtual API Vulnerable] Servidor ejecutándose en http://localhost:${PORT}`);
});