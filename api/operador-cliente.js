// Función serverless de Vercel: /api/operador-cliente
// Devuelve el detalle de un cliente puntual para el panel operador: sus
// datos de perfil, sus contactos de emergencia y su historial de alertas
// (todas, no solo las activas). Igual que los otros endpoints de operador,
// verifica el idToken contra Firebase Auth y confirma que sea la cuenta
// central antes de leer nada, y usa la cuenta de servicio para leer
// Firestore vía REST (sin depender de las reglas de seguridad del cliente).

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

async function obtenerCliente(accessToken, clienteUid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return null;
  const doc = await resp.json();
  const f = doc.fields || {};
  return {
    uid: clienteUid,
    nombre: f.nombre?.stringValue || '',
    local: f.local?.stringValue || '',
    direccion: f.direccion?.stringValue || '',
    telefono: f.telefono?.stringValue || '',
    modo: f.modo?.stringValue || 'empresa',
    rolEmpresa: f.rolEmpresa?.stringValue || '',
    grupoFamiliarId: f.grupoFamiliarId?.stringValue || '',
    claveSeguridad: f.claveSeguridad?.stringValue || '',
    notaCentral: f.notaCentral?.stringValue || '',
    claveCoaccion: f.claveCoaccion?.stringValue || ''
  };
}

async function listarContactos(accessToken, clienteUid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/contactos?pageSize=100`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return [];
  const data = await resp.json();
  const docs = data.documents || [];
  return docs.map((doc) => {
    const f = doc.fields || {};
    return {
      id: doc.name.split('/').pop(),
      nombre: f.nombre?.stringValue || '',
      chatId: f.chatId?.stringValue || '',
      telefono: f.telefono?.stringValue || '',
      activo: f.activo?.booleanValue !== false
    };
  });
}

async function listarAlertasCliente(accessToken, clienteUid) {
  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/alertas` +
    `?pageSize=20&orderBy=${encodeURIComponent('creadaEn desc')}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return [];
  const data = await resp.json();
  const docs = data.documents || [];
  return docs.map((doc) => {
    const f = doc.fields || {};
    const ubic = f.ubicacion?.mapValue?.fields;
    return {
      alertaId: doc.name.split('/').pop(),
      estado: f.estado?.stringValue || '',
      creadaEn: f.creadaEn?.timestampValue || null,
      atendidaEn: f.atendidaEn?.timestampValue || null,
      canceladaEn: f.canceladaEn?.timestampValue || null,
      ubicacion: ubic
        ? {
            lat: parseFloat(ubic.lat?.doubleValue ?? ubic.lat?.integerValue ?? 0),
            lng: parseFloat(ubic.lng?.doubleValue ?? ubic.lng?.integerValue ?? 0)
          }
        : null
    };
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }

  const { idToken, clienteUid } = req.body || {};
  if (!idToken || !clienteUid) {
    res.status(400).json({ error: 'Faltan datos (idToken o clienteUid)' });
    return;
  }

  try {
    const uid = await verificarOperador(idToken);
    if (!esOperador(uid)) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }

    const accessToken = await obtenerAccessToken();
    const [cliente, contactos, alertas] = await Promise.all([
      obtenerCliente(accessToken, clienteUid),
      listarContactos(accessToken, clienteUid),
      listarAlertasCliente(accessToken, clienteUid)
    ]);

    if (!cliente) {
      res.status(404).json({ error: 'Cliente no encontrado' });
      return;
    }

    res.status(200).json({ ok: true, cliente, contactos, alertas });
  } catch (err) {
    console.error('Error en detalle de cliente (operador):', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
