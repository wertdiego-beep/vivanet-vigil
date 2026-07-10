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

// Lee el/los token(s) FCM guardados en el documento de la central directamente
// desde Firestore vía REST, usando el access token de la cuenta de servicio
// (esto no pasa por las reglas de seguridad del cliente).
async function obtenerTokenCentral(accessToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${CENTRAL_UID}`;
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

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
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

    const tokenCentral = await obtenerTokenCentral(accessToken);
    if (tokenCentral) {
      resultados.central = await enviarPush(accessToken, tokenCentral, tituloCentral, cuerpoCentral);
    } else {
      resultados.central = { ok: false, motivo: 'La central no ha activado notificaciones push todavía' };
    }

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
