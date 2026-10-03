# Marco Normativo Organizacional (ONF) - ISO/IEC 27034
**Aplicación:** CampusVirtual API (Caso 3)  
**Entidad:** Sistema Universitario EduTech  
**Norma:** ISO/IEC 27034-1 (Information technology — Security techniques — Application security)  

---

## 1. Propósito y Alcance del ONF
El presente Marco Normativo Organizacional (Organization Normative Framework - ONF) establece los principios, directrices de gobernanza y requerimientos de seguridad obligatorios que deben regir durante todo el ciclo de vida del software en CampusVirtual API. Su objetivo es asegurar que la aplicación alcance y mantenga un Nivel de Confianza de Seguridad de la Aplicación (ASCL) acorde al riesgo institucional.

---

## 2. Clasificación de Criticidad de Activos de Información

| Activo | Tipo de Dato | Confidencialidad | Integridad | Disponibilidad | Impacto ante Falla |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Calificaciones** | Registro académico de notas | Alta | **Crítica** | Alta | Daño reputacional severo e invalidación de títulos |
| **Exámenes y Pautas** | Evaluaciones en curso y bancos de preguntas | **Crítica** | **Crítica** | **Crítica** | Filtración previa de exámenes y fraude académico |
| **Credenciales** | Hashes de acceso y tokens JWT | **Crítica** | Alta | Alta | Suplantación de identidad docente y administrativa |
| **RUT / Datos Personales** | Información de identidad ciudadana | Alta | Alta | Media | Vulneración de normativas de protección de datos |

---

## 3. Integración en el Ciclo de Vida del Software (ASLCRM)
De acuerdo con la norma ISO/IEC 27034, el ciclo de vida de desarrollo de la plataforma debe incorporar las siguientes compuertas de seguridad:

1. **Definición de Requisitos:** Determinación obligatoria de los Controles de Seguridad de la Aplicación (ASC) antes de iniciar la codificación.
2. **Diseño Seguro:** Aplicación de arquitecturas de confianza cero (Zero Trust Input), separación estricta de privilegios de usuario y validación temporal centralizada en el backend.
3. **Codificación Segura:** Rechazo estricto de concatenación de consultas en bases de datos y utilización de librerías criptográficas vigentes.
4. **Verificación y Auditoría:** Ejecución mandatoria de pruebas automáticas con herramientas de penetración (curl / SAST / DAST) antes del despliegue.