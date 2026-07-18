// Función serverless de Vercel: /api/send-push
// Envía notificaciones push reales (Firebase Cloud Messaging) cuando se activa
// un SOS: una a la central (dueño del negocio) y opcionalmente una de
// confirmación al propio usuario que activó la alerta.
//
// No usa el paquete firebase-admin (para no agregar dependencias): firma su
// propio JWT con la cuenta de servicio y llama directamente a las APIs REST
// de Google (OAuth2 + FCM v1 + Firestore). Las credenciales de la cuenta de
// servicio quedan ocultas en variables de entorno de Vercel.

import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
const CENTRAL_UID = 'ziDCZASJ7GaMoBhUDw7uPbKmFgE2'; // cuenta de Diego (central)
// Todos los operadores de la central reciben el push (no solo la cuenta
// original). Se definen en Vercel con OPERADORES_UIDS (uids separados por coma).
const OPERADORES = (process.env.OPERADORES_UIDS || CENTRAL_UID).split(',').map((s) => s.trim()).filter(Boolean);

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

// Lee el token FCM guardado en el documento de un usuario directamente
// desde Firestore vía REST, usando el access token de la cuenta de servicio
// (esto no pasa por las reglas de seguridad del cliente).
async function obtenerTokenUsuario(accessToken, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`;
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!resp.ok) return null;
  const data = await resp.json();
  const token = data.fields?.fcmToken?.stringValue;
  return token || null;
}

async function enviarPush(accessToken, token, titulo, cuerpo) {
  const resp = await fetch(`https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      message: {
        token,
        notification: { title: titulo, body: cuerpo },
        webpush: {
          notification: { icon: '/icon-192.png' },
          fcm_options: { link: '/' }
        }
      }
    })
  });
  const data = await resp.json();
  return { ok: resp.ok, status: resp.status, data };
}

const FIREBASE_API_KEY = 'AIzaSyCRAFZXVB6VZ8vAVoMF3WDvjcmUCiInP2g'; // clave pública del cliente web
const OPERADORES = (process.env.OPERADORES_UIDS || CENTRAL_UID).split(',').map((s) => s.trim()).filter(Boolean);

// ── DIFUSIÓN MASIVA: un operador envía un aviso push a TODOS los clientes de
// su empresa que tengan notificaciones activadas (espec. 27 y 40 del pliego).
async function manejarDifusion(req, res) {
  const { idToken, titulo, cuerpo } = req.body || {};
  if (!idToken || !titulo || !cuerpo) { res.status(400).json({ error: 'Faltan idToken, título o cuerpo' }); return; }
  const accessToken = await obtenerAccessToken();
  // Verificar que quien envía es un operador.
  const lookup = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  }).then((r) => r.json());
  const uid = lookup.users && lookup.users[0] && lookup.users[0].localId;
  if (!uid) { res.status(401).json({ error: 'Sesión no válida' }); return; }
  const docOp = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
  const esOp = OPERADORES.includes(uid) || !!docOp.fields?.operadorDe?.stringValue;
  if (!esOp) { res.status(403).json({ error: 'Solo operadores pueden enviar difusiones' }); return; }
  const empOp = docOp.fields?.operadorDe?.stringValue || docOp.fields?.empresaId?.stringValue || 'sos360-la-serena';
  // Clientes de SU empresa con push activado.
  const lista = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios?pageSize=300`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
  const destinos = (lista.documents || []).filter((d) => {
    const f = d.fields || {};
    const emp = f.empresaId?.stringValue || 'sos360-la-serena';
    const id = d.name.split('/').pop();
    return emp === empOp && f.fcmToken?.stringValue && id !== uid && !OPERADORES.includes(id) && !f.operadorDe?.stringValue;
  }).slice(0, 200);
  let enviados = 0;
  for (const d of destinos) {
    const r = await enviarPush(accessToken, d.fields.fcmToken.stringValue, `📣 ${titulo}`, cuerpo);
    if (r.ok) enviados++;
  }
  res.status(200).json({ ok: true, enviados, totalConPush: destinos.length });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }

  if (req.body && req.body.accion === 'difusion') {
    try { await manejarDifusion(req, res); } catch (err) { res.status(500).json({ error: err.message }); }
    return;
  }

  const { tituloCentral, cuerpoCentral, propioToken, tituloPropio, cuerpoPropio } = req.body || {};

  if (!tituloCentral || !cuerpoCentral) {
    res.status(400).json({ error: 'Falta tituloCentral o cuerpoCentral' });
    return;
  }

  try {
    const accessToken = await obtenerAccessToken();
    const resultados = {};

    // Push a TODOS los operadores que tengan notificaciones activadas.
    const tokens = await Promise.all(OPERADORES.map((uid) => obtenerTokenUsuario(accessToken, uid)));
    const envios = await Promise.all(tokens.filter(Boolean).map((t) => enviarPush(accessToken, t, tituloCentral, cuerpoCentral)));
    resultados.central = envios.length
      ? { ok: envios.some((e) => e.ok), enviados: envios.length }
      : { ok: false, motivo: 'Ningún operador ha activado notificaciones push todavía' };

    if (propioToken) {
      resultados.propio = await enviarPush(
        accessToken,
        propioToken,
        tituloPropio || tituloCentral,
        cuerpoPropio || cuerpoCentral
      );
    }

    res.status(200).json({ ok: true, resultados });
  } catch (err) {
    console.error('Error enviando notificación push:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
