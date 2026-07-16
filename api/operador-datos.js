// Función serverless de Vercel: /api/operador-datos
// Devuelve, solo para la cuenta central (Diego), la lista de clientes y las
// alertas SOS activas de todos ellos. Verifica primero el idToken del que
// llama contra Firebase Auth (accounts:lookup) y confirma que su UID sea el
// de la central; si no, responde 403. Luego usa la cuenta de servicio para
// leer Firestore vía REST, sin depender de las reglas de seguridad del
// cliente (igual que /api/send-push).

import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
const CENTRAL_UID = 'ziDCZASJ7GaMoBhUDw7uPbKmFgE2'; // cuenta de Diego (central)
// Operadores autorizados de la central. Se definen en Vercel con la variable
// OPERADORES_UIDS (uids separados por coma). Si no existe, queda solo la
// cuenta central original, así nada cambia hasta que agregues operadores.
const OPERADORES = (process.env.OPERADORES_UIDS || CENTRAL_UID).split(',').map((s) => s.trim()).filter(Boolean);
const esOperador = (uid) => !!uid && OPERADORES.includes(uid);
const FIREBASE_API_KEY = 'AIzaSyCRAFZXVB6VZ8vAVoMF3WDvjcmUCiInP2g'; // clave pública del cliente web (no es secreta)

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function obtenerAccessToken() {
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');

  if (!clientEmail || !privateKey) {
    throw new Error('Faltan credenciales de Firebase en Vercel (FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY)');
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    iat: nowSec,
    exp: nowSec + 3600
  };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();
  const signature = signer
    .sign(privateKey)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const jwt = `${unsigned}.${signature}`;

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    })
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error('No se pudo obtener el token de acceso: ' + JSON.stringify(data));
  }
  return data.access_token;
}

// Verifica el idToken del que llama contra Firebase Auth y devuelve su UID
// (o null si no es válido). No usamos firebase-admin: llamamos directo a la
// API REST de Identity Toolkit con la clave pública del proyecto.
async function verificarOperador(idToken) {
  const resp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });
  const data = await resp.json();
  if (!resp.ok || !data.users || !data.users[0]) return null;
  return data.users[0].localId;
}

async function listarClientes(accessToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios?pageSize=300`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return [];
  const data = await resp.json();
  const docs = data.documents || [];
  return docs
    .map((doc) => {
      const id = doc.name.split('/').pop();
      const f = doc.fields || {};
      return {
        uid: id,
        nombre: f.nombre?.stringValue || '',
        local: f.local?.stringValue || '',
        direccion: f.direccion?.stringValue || '',
        telefono: f.telefono?.stringValue || '',
        modo: f.modo?.stringValue || 'empresa',
        rolEmpresa: f.rolEmpresa?.stringValue || '',
        grupoFamiliarId: f.grupoFamiliarId?.stringValue || ''
      };
    })
    .filter((c) => !esOperador(c.uid));
}

// IMPORTANTE: antes las alertas activas se pedían con una consulta filtrada
// (where estado == 'activa') sobre el grupo de colecciones "alertas". Ese
// tipo de consulta requiere un índice de grupo de colecciones en Firestore
// que este proyecto no tiene, así que Firestore respondía con error, el
// código lo tragaba con "return []" y el panel SIEMPRE mostraba 0 alertas
// activas (aunque el historial —que usa la consulta SIN filtro— sí las
// mostraba). Ahora las activas se derivan en JS desde esa misma consulta
// sin filtro, que no necesita ningún índice.
function derivarAlertasActivas(alertasRecientes) {
  // Una alerta "activa" con más de 12 horas se considera vencida (quedó
  // huérfana de alguna prueba o de un cierre que falló) y no se muestra
  // como emergencia vigente.
  const corte = Date.now() - 12 * 3600 * 1000;
  return alertasRecientes
    .filter((a) => a.estado === 'activa' && a.creadaEn && new Date(a.creadaEn).getTime() >= corte)
    .slice(0, 50);
}

// Trae hasta 120 alertas recientes (de cualquier estado, de cualquier
// cliente) sin filtro, para armar el historial general y las estadísticas.
// Antes traía 300, pero como este endpoint se consulta en cada actualización
// del panel operador, ese límite alto multiplicaba mucho las lecturas de
// Firestore y agotaba la cuota gratuita diaria. 120 alcanza para el
// historial visible (20), las estadísticas del día y las alertas activas.
// No usamos "where"/"orderBy" combinados para evitar depender de un índice
// compuesto en Firestore; ordenamos y filtramos acá mismo, en JS.
async function listarAlertasRecientes(accessToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'alertas', allDescendants: true }],
      limit: 120
    }
  };
  const resp = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!resp.ok) return [];
  const data = await resp.json();
  return (data || [])
    .filter((r) => r.document)
    .map((r) => {
      const doc = r.document;
      const parts = doc.name.split('/');
      const alertaId = parts.pop();
      parts.pop(); // 'alertas'
      const uid = parts.pop();
      const f = doc.fields || {};
      const ubic = f.ubicacion?.mapValue?.fields;
      return {
        clienteUid: uid,
        alertaId,
        estado: f.estado?.stringValue || '',
        creadaEn: f.creadaEn?.timestampValue || null,
        atendidaEn: f.atendidaEn?.timestampValue || null,
        canceladaEn: f.canceladaEn?.timestampValue || null,
        resultado: f.resultado?.stringValue || '',
        notaAtencion: f.notaAtencion?.stringValue || '',
        atendidaPor: f.atendidaPor?.stringValue || '',
        asignadaA: f.asignadaA?.stringValue || '',
        ubicacion: ubic
          ? {
              lat: parseFloat(ubic.lat?.doubleValue ?? ubic.lat?.integerValue ?? 0),
              lng: parseFloat(ubic.lng?.doubleValue ?? ubic.lng?.integerValue ?? 0),
              precision: parseFloat(ubic.precision?.doubleValue ?? ubic.precision?.integerValue ?? 0)
            }
          : null
      };
    })
    .sort((a, b) => new Date(b.creadaEn || 0) - new Date(a.creadaEn || 0));
}

// Obtiene el código de equipo de la central (Diego) vía la cuenta de
// servicio, generándolo y guardándolo si todavía no existe. Se hace acá (en
// vez de con el SDK del cliente) porque las reglas de seguridad de Firestore
// no le permiten a la cuenta central escribir su propio documento desde el
// navegador, por lo que un .set() directo desde el cliente fallaba en
// silencio y mostraba un código que nunca quedaba realmente guardado.
async function obtenerOGenerarCodigoOperador(accessToken, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (resp.ok) {
    const doc = await resp.json();
    const codigoExistente = doc.fields?.codigoFamilia?.stringValue;
    if (codigoExistente) return { codigo: codigoExistente, creado: false };
  }
  const codigo = uid.slice(0, 6).toUpperCase();
  const patchUrl = `${url}?updateMask.fieldPaths=codigoFamilia`;
  const patchResp = await fetch(patchUrl, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { codigoFamilia: { stringValue: codigo } } })
  });
  if (!patchResp.ok) {
    const errData = await patchResp.json().catch(() => ({}));
    throw new Error('No se pudo guardar el código: ' + (errData.error?.message || patchResp.status));
  }
  return { codigo, creado: true };
}

function calcularStats(alertasRecientes) {
  const hoy = new Date();
  hoy.setHours(0, 0, 0, 0);
  const alertasHoy = alertasRecientes.filter((a) => a.creadaEn && new Date(a.creadaEn) >= hoy).length;

  const tiempos = alertasRecientes
    .filter((a) => a.creadaEn && a.atendidaEn)
    .map((a) => (new Date(a.atendidaEn) - new Date(a.creadaEn)) / 60000)
    .filter((min) => min >= 0 && min < 24 * 60);

  const tiempoPromedioResp = tiempos.length
    ? Math.round((tiempos.reduce((a, b) => a + b, 0) / tiempos.length) * 10) / 10
    : null;

  return { alertasHoy, tiempoPromedioResp };
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }

  const { idToken, accion } = req.body || {};
  if (!idToken) {
    res.status(400).json({ error: 'Falta idToken' });
    return;
  }

  try {
    const uid = await verificarOperador(idToken);
    if (!esOperador(uid)) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }

    const accessToken = await obtenerAccessToken();

    if (accion === 'codigo') {
      const resultado = await obtenerOGenerarCodigoOperador(accessToken, uid);
      res.status(200).json({ ok: true, codigo: resultado.codigo, creado: resultado.creado });
      return;
    }

    const [clientes, alertasRecientes] = await Promise.all([
      listarClientes(accessToken),
      listarAlertasRecientes(accessToken)
    ]);
    const alertas = derivarAlertasActivas(alertasRecientes);

    const stats = calcularStats(alertasRecientes);
    stats.totalActivas = alertas.length;
    stats.totalClientes = clientes.length;

    const historial = alertasRecientes.slice(0, 120);

    res.status(200).json({ ok: true, clientes, alertas, historial, stats });
  } catch (err) {
    console.error('Error en panel operador:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
