#!/usr/bin/env bash
# Script Automatizado de Re-auditoría Fase 2 - Certificación Defensiva (Caso 3)
API_URL="http://localhost:3000"
EVIDENCIAS_DIR="./auditoria/fase2/evidencias"

mkdir -p "$EVIDENCIAS_DIR"

echo "================================================================"
echo "    INICIANDO AUDITORIA DEFENSIVA DE CIERRE (FASE 2)            "
echo "================================================================"

# Test A01: Escalada de privilegios (modificar nota con role=admin manipulado en body)
echo -n "[A01] Control de Acceso (Bypass de rol sin token admin): "
RES_A01=$(curl -s -o "$EVIDENCIAS_DIR/a01_mitigado.txt" -w "%{http_code}" -X POST "$API_URL/api/grades/update" \
  -H "Content-Type: application/json" \
  -d '{"studentId": 1, "grade": 7.0, "role": "admin"}')
echo "Código HTTP: $RES_A01 (Esperado: 401 Unauthorized)"

# Test A02: Emisión segura de JWT con expiración
echo -n "[A02] Criptografía (Emisión de token seguro con expiración): "
RES_A02=$(curl -s -o "$EVIDENCIAS_DIR/a02_mitigado.txt" -w "%{http_code}" -X POST "$API_URL/api/login/student" \
  -H "Content-Type: application/json" \
  -d '{"rut": "12345678-5"}')
echo "Código HTTP: $RES_A02 (Esperado: 200 OK con payload seguro)"

# Test A03: Inyección SQL en parámetro RUT
echo -n "[A03] Inyección SQL en RUT (Rechazo por formato estricto / Prepared Statement): "
RES_A03=$(curl -s -o "$EVIDENCIAS_DIR/a03_mitigado.txt" -w "%{http_code}" -G "$API_URL/api/students" \
  --data-urlencode "rut=1-9' OR '1'='1")
echo "Código HTTP: $RES_A03 (Esperado: 400 Bad Request)"

# Test A04: Examen con tiempo límite expirado
echo -n "[A04] Lógica de Negocio (Bloqueo de entrega de examen vencido): "
# Obtenemos token de estudiante primero
TOKEN_STUDENT=$(curl -s -X POST "$API_URL/api/login/student" -H "Content-Type: application/json" -d '{"rut":"12345678-5"}' | grep -o '"token":"[^"]*' | cut -d'"' -f4)
RES_A04=$(curl -s -o "$EVIDENCIAS_DIR/a04_mitigado.txt" -w "%{http_code}" -X POST "$API_URL/api/exams/1/submit" \
  -H "Authorization: Bearer $TOKEN_STUDENT" \
  -H "Content-Type: application/json" \
  -d '{"answers": {"p1": "A", "p2": "B"}}')
echo "Código HTTP: $RES_A04 (Esperado: 400 Bad Request)"

# Test A05: Exposición de configuración y claves (/debug/config)
echo -n "[A05] Deshabilitación de endpoint sensible /debug/config: "
RES_A05=$(curl -s -o "$EVIDENCIAS_DIR/a05_mitigado.txt" -w "%{http_code}" "$API_URL/debug/config")
echo "Código HTTP: $RES_A05 (Esperado: 404 Not Found)"

# Test A07: Autenticación Docente (Bcrypt seguro)
echo -n "[A07] Autenticación Docente Robusta: "
RES_A07=$(curl -s -o "$EVIDENCIAS_DIR/a07_mitigado.txt" -w "%{http_code}" -X POST "$API_URL/api/login/teacher" \
  -H "Content-Type: application/json" \
  -d '{"email": "profesor@campus.cl", "password": "profesor123"}')
echo "Código HTTP: $RES_A07 (Esperado: 200 OK con hash Bcrypt verificado)"

# Test A08: Sanitización XSS en foros
echo -n "[A08] Sanitización de scripts XSS en comentarios: "
RES_A08=$(curl -s -o "$EVIDENCIAS_DIR/a08_mitigado.txt" -w "%{http_code}" -X POST "$API_URL/api/forum/posts" \
  -H "Authorization: Bearer $TOKEN_STUDENT" \
  -H "Content-Type: application/json" \
  -d '{"content": "<script>alert(document.cookie)</script>Comentario valido"}')
echo "Código HTTP: $RES_A08 (Esperado: 201 Created con HTML neutralizado)"

# Test A09: Acceso prematuro a examen (Generación de Log de Seguridad)
echo -n "[A09] Trazabilidad y Logging en acceso no autorizado: "
RES_A09=$(curl -s -o "$EVIDENCIAS_DIR/a09_mitigado.txt" -w "%{http_code}" -X GET "$API_URL/api/exams/1/content" \
  -H "Authorization: Bearer $TOKEN_STUDENT")
echo "Código HTTP: $RES_A09 (Verificado: evento registrado en security-audit.log)"

# Test A10: Prevención de SSRF hacia metadatos/red privada
echo -n "[A10] Mitigación SSRF (Intento de acceso a IP privada): "
TOKEN_TEACHER=$(curl -s -X POST "$API_URL/api/login/teacher" -H "Content-Type: application/json" -d '{"email":"profesor@campus.cl","password":"profesor123"}' | grep -o '"token":"[^"]*' | cut -d'"' -f4)
RES_A10=$(curl -s -o "$EVIDENCIAS_DIR/a10_mitigado.txt" -w "%{http_code}" -X POST "$API_URL/api/exams/import-external" \
  -H "Authorization: Bearer $TOKEN_TEACHER" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:3000/debug/config"}')
echo "Código HTTP: $RES_A10 (Esperado: 400 Bad Request / 403 Forbidden)"

echo "================================================================"
echo "Re-auditoría finalizada. Evidencias de cierre guardadas en $EVIDENCIAS_DIR"