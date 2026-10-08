# Hifa 1.1 · paquete completo

## Qué hay aquí

| Carpeta | Contenido |
|---|---|
| `1-app-hifa/` | La app lista para publicar. **Esta es la carpeta que subes al hosting.** |
| `2-documentos/` | Instrucciones de instalación, manual para pacientes, guía para profesionales, documento técnico y manual de marca (PDF). |
| `LEEME.md` | Esta guía. |

Hifa guarda todo **cifrado en el dispositivo** (AES-256, con tu clave). No hay servidor de datos ni cuentas: el hosting solo entrega los archivos de la app; tus datos nunca pasan por ahí.

La misma app sirve para dos usos, que eliges al crear la clave:
- **Para mí** (paciente): bitácora, registro, panel, escalas, informe y envío cifrado a tu psicólogx.
- **Como profesional**: lista de pacientes, alertas, gráfico, resumen y notas privadas de sesión.

---

## Paso 1 · Publicar la app (una sola vez, desde el computador)

Para instalarse en el celular, una web app tiene que estar en una dirección `https://`. Abrir el archivo directamente no funciona. **No necesitas Replit**: sirve cualquier hosting estático gratuito.

### Opción A · Netlify Drop (la más fácil, 2 minutos)
1. Entra a **app.netlify.com/drop**.
2. Arrastra la carpeta `1-app-hifa` completa.
3. Te da una dirección `https://algo.netlify.app`. Crea una cuenta gratis para que el sitio no expire y, si quieres, cámbiale el nombre (p. ej. `mi-hifa.netlify.app`).

### Opción B · GitHub Pages (gratis y permanente)
1. Crea una cuenta en **github.com** → **New repository** (por ejemplo `hifa`), público.
2. **Add file → Upload files** → arrastra el **contenido** de `1-app-hifa` (no la carpeta, lo de adentro) → **Commit**.
3. **Settings → Pages → Branch: main / (root) → Save**.
4. En 1 o 2 minutos queda en `https://tuusuario.github.io/hifa/`.

### Opción C · Cloudflare Pages
**dash.cloudflare.com → Workers & Pages → Create → Pages → Upload assets** → sube la carpeta. Te da `https://algo.pages.dev`.

### Opción D · Replit
App nueva con plantilla **HTML, CSS, JS** → borra los archivos de ejemplo → arrastra el contenido de `1-app-hifa` → **Deploy → Static** (directorio raíz, sin comando de compilación).

> Cualquiera puede abrir tu dirección, pero cada persona ve **su propia Hifa vacía**: los datos viven en cada dispositivo, no en el sitio. Tú y tu psicólogx pueden usar la misma dirección.

---

## Paso 2 · Instalar en el celular

### Android (Chrome)
1. Abre tu dirección `https://…` en **Chrome**.
2. Menú **⋮** → **Instalar app** (o **Agregar a pantalla principal**).
3. Ábrela siempre desde el ícono de la seta.

### iPhone (Safari)
1. Abre tu dirección en **Safari** (no en Chrome ni dentro de Instagram o WhatsApp).
2. Botón **Compartir** → **Agregar a pantalla de inicio** → **Agregar**.
3. **Úsala siempre desde el ícono.** En iPhone la app instalada guarda sus datos aparte de Safari.

### Computador (opcional)
Chrome o Edge → ícono de **instalar** en la barra de direcciones. Ahí puedes activar **Copia automática en un archivo** (Yo › Mis datos y copias).

---

## Paso 3 · Primer uso

1. Elige **Para mí** o **Como profesional** y **crea tu clave** (mínimo 8 caracteres). Si la olvidas, **nadie** puede recuperar los datos.
2. **Haz tu primera copia:** Mis datos y copias › **Hacer copia ahora**. En el celular se abre el menú de compartir: guárdala en Drive, iCloud/Archivos o envíatela por correo. El archivo está cifrado.
3. **Agrega los recordatorios a tu calendario** (en la misma sección). Hifa no envía notificaciones cuando está cerrada.

---

## Paso 4 · Conectar paciente y psicólogx (sin servidor)

**Psicólogx** (instala Hifa y elige *Como profesional*):
1. Pestaña **Mi código** → escribe tu nombre → **Compartir código** (por WhatsApp, por ejemplo).

**Paciente:**
2. **Yo › Mi psicólogx › Vínculo** → pega el código → **Vincular**.
3. En la próxima sesión, comparen la **huella** (por ejemplo `A4DD-0EA8-AD65`). Si es igual en los dos celulares, el vínculo es seguro.
4. Antes de cada sesión: **Enviar a mi psicólogx** → elige qué incluir y el periodo → **Crear paquete cifrado y enviar** → mándalo por WhatsApp o correo.

**Psicólogx:**
5. Guarda el archivo recibido → pestaña **Pacientes** → **Importar paquete**.
6. Ve alertas (racha baja, PHQ-9, pregunta 9, riesgo con psicodélicos, macrodosis), gráfico, resumen y escribe **notas privadas** que solo quedan en su dispositivo.

El paquete viaja cifrado: aunque pase por WhatsApp, solo la Hifa de ese profesional puede abrirlo. Cada paquete nuevo se suma al historial del paciente.

**Lo que no hace esta versión** (necesita servidor): ver datos en tiempo real, enviar escalas o tareas desde la app del profesional, avisos automáticos de riesgo. Por eso **Hifa no reemplaza la atención de crisis**.

---

## Si cambias o pierdes el celular
Instala Hifa en el nuevo → **Ya tengo una copia (.json)** → elige el archivo → escribe la clave con la que hiciste esa copia. Esto vale para pacientes y profesionales.

## Bueno saber
- **Bloqueo automático:** tras 5 minutos en segundo plano, vuelve a pedir la clave.
- **Sin internet:** después de abrirla una vez, funciona sin conexión.
- **Dictado por voz:** lo procesa tu navegador o tu teclado (puede usar servicios de Google o Apple).
- **PHQ-9 y GAD-7** son escalas de tamizaje de uso libre. No son un diagnóstico.
- **Hifa no recomienda dosis ni combinaciones**; solo guarda lo que anotas.

## Actualizar la app más adelante
Reemplaza los archivos en tu hosting. Antes, cambia la versión en la línea `const VERSION` de `sw.js` (p. ej. `hifa-v1.1.1`) para que los dispositivos descarguen la nueva. Los datos no se tocan.

**Mantén la misma dirección.** Los datos quedan ligados a la dirección del sitio: si la cambias, cada persona debe instalar Hifa desde la nueva y restaurar su copia.

## Qué queda para versiones con servidor
Conversación con IA real · notificaciones push · vista profesional en tiempo real · directorio y cotizaciones · avisos por correo o WhatsApp. Todo está diseñado en `2-documentos`.
