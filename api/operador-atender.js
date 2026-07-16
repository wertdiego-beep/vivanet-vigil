// Función serverless de Vercel: /api/operador-atender
// Permite que la cuenta central (Diego) marque una alerta SOS de un cliente
// como "atendida". Verifica el idToken igual que /api/operador-datos y
// escribe directamente en Firestore vía REST con la cuenta de servicio
// (bypass de las reglas de seguridad del cliente).

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

// Marca que un operador tomó la alerta (sin cerrarla): así otros operadores
// ven que ya está siendo atendida y no se duplica el trabajo.
async function asignarAlerta(accessToken, clienteUid, alertaId, operador) {
  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/alertas/${alertaId}` +
    `?updateMask.fieldPaths=asignadaA&updateMask.fieldPaths=asignadaEn`;
  const body = {
    fields: {
      asignadaA: { stringValue: operador || '' },
      asignadaEn: { timestampValue: new Date().toISOString() }
    }
  };
  const resp = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await resp.json();
  return { ok: resp.ok, status: resp.status, data };
}

async function marcarAtendida(accessToken, clienteUid, alertaId, resultado, nota, operador) {
  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/alertas/${alertaId}` +
    `?updateMask.fieldPaths=estado&updateMask.fieldPaths=atendidaEn&updateMask.fieldPaths=resultado&updateMask.fieldPaths=notaAtencion&updateMask.fieldPaths=atendidaPor`;
  const body = {
    fields: {
      estado: { stringValue: 'atendida' },
      atendidaEn: { timestampValue: new Date().toISOString() },
      resultado: { stringValue: resultado || '' },
      notaAtencion: { stringValue: nota || '' },
      atendidaPor: { stringValue: operador || '' }
    }
  };
  const resp = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await resp.json();
  return { ok: resp.ok, status: resp.status, data };
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }

  const { idToken, clienteUid, alertaId, resultado, nota, operador, accion } = req.body || {};
  if (!idToken || !clienteUid || !alertaId) {
    res.status(400).json({ error: 'Faltan datos (idToken, clienteUid o alertaId)' });
    return;
  }

  try {
    const uid = await verificarOperador(idToken);
    if (!esOperador(uid)) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }

    const accessToken = await obtenerAccessToken();
    if (accion === 'asignar') {
      const rAsig = await asignarAlerta(accessToken, clienteUid, alertaId, operador);
      res.status(200).json({ ok: true, asignada: rAsig });
      return;
    }
    const rMarcar = await marcarAtendida(accessToken, clienteUid, alertaId, resultado, nota, operador);
    res.status(200).json({ ok: true, resultado: rMarcar });
  } catch (err) {
    console.error('Error marcando alerta como atendida:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
