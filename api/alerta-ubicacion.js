// Función serverless de Vercel: /api/alerta-ubicacion
// Actualiza la ubicación (o cancela) una alerta SOS del propio usuario.
//
// ¿Por qué existe? Las reglas de seguridad de Firestore permiten al cliente
// CREAR su alerta, pero no editarla después. Por eso la ubicación GPS llegaba
// a Telegram (que va por servidor) pero nunca quedaba guardada en la alerta,
// y el panel de la central no podía mostrar el punto en el mapa.
//
// Seguridad: se verifica el idToken del que llama contra Firebase Auth y el
// UID resultante define QUÉ alerta puede tocar (solo las suyas). La escritura
// se hace con la cuenta de servicio, igual que /api/operador-datos.

import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
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
    scope: 'https://www.googleapis.com/auth/datastore',
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

// Verifica el idToken y devuelve el UID del usuario (o null si no es válido).
async function verificarUsuario(idToken) {
  const resp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });
  const data = await resp.json();
  if (!resp.ok || !data.users || !data.users[0]) return null;
  return data.users[0].localId;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }

  const { idToken, alertaId, lat, lng, accion, precision } = req.body || {};

  if (!idToken || !alertaId || typeof alertaId !== 'string') {
    res.status(400).json({ error: 'Faltan idToken o alertaId' });
    return;
  }

  const esCancelacion = accion === 'cancelar';
  if (!esCancelacion && (typeof lat !== 'number' || typeof lng !== 'number')) {
    res.status(400).json({ error: 'Faltan coordenadas lat/lng' });
    return;
  }

  try {
    const uid = await verificarUsuario(idToken);
    if (!uid) {
      res.status(403).json({ error: 'Sesión no válida' });
      return;
    }

    const accessToken = await obtenerAccessToken();
    const ahora = new Date().toISOString();

    // Solo puede tocar SUS alertas: la ruta usa el uid verificado del token.
    const docPath = `projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}/alertas/${encodeURIComponent(alertaId)}`;

    let campos, mascara;
    if (esCancelacion) {
      campos = {
        estado: { stringValue: 'cancelada' },
        canceladaEn: { timestampValue: ahora }
      };
      mascara = 'updateMask.fieldPaths=estado&updateMask.fieldPaths=canceladaEn';
    } else {
      campos = {
        ubicacion: { mapValue: { fields: { lat: { doubleValue: lat }, lng: { doubleValue: lng }, precision: { doubleValue: (typeof precision === "number" && isFinite(precision)) ? precision : 0 } } } },
        ultimaActualizacion: { timestampValue: ahora }
      };
      mascara = 'updateMask.fieldPaths=ubicacion&updateMask.fieldPaths=ultimaActualizacion';
    }

    const resp = await fetch(`https://firestore.googleapis.com/v1/${docPath}?${mascara}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: campos })
    });

    if (!resp.ok) {
      const detalle = await resp.text();
      console.error('Error escribiendo en Firestore:', detalle);
      res.status(500).json({ error: 'No se pudo actualizar la alerta' });
      return;
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Error en alerta-ubicacion:', err);
    res.status(500).json({ error: 'Error interno' });
  }
}
