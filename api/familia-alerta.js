// Función serverless de Vercel: /api/familia-alerta
// Cuando un integrante de una familia (padre o hijo) activa el botón SOS,
// esta función avisa por notificación push a TODOS los demás integrantes del
// mismo grupo familiar (no solo a la central), para que sepan de inmediato
// si un familiar activó una alarma. Usa la cuenta de servicio para leer
// Firestore y enviar FCM, sin depender de las reglas de seguridad del cliente
// (mismo patrón que /api/send-push y /api/operador-datos).

import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
const FIREBASE_API_KEY = 'AIzaSyCRAFZXVB6VZ8vAVoMF3WDvjcmUCiInP2g'; // clave pública del cliente web (no es secreta)
const FIREBASE_SERVER_API_KEY = process.env.FIREBASE_SERVER_API_KEY || FIREBASE_API_KEY; // key de servidor (server-to-server, sin restricción de referrer)

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

async function verificarUsuario(idToken) {
  const resp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_SERVER_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });
  const data = await resp.json();
  if (!resp.ok || !data.users || !data.users[0]) return null;
  return data.users[0].localId;
}

async function crearAviso(accessToken, uid, mensaje, email, lat, lng) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}/avisos`;
  const fields = {
    tipo: { stringValue: 'sos-familia' },
    mensaje: { stringValue: mensaje },
    creadoEn: { timestampValue: new Date().toISOString() },
    leido: { booleanValue: false }
  };
  if (email) fields.email = { stringValue: String(email) };
  if (typeof lat === 'number' && isFinite(lat)) fields.lat = { doubleValue: lat };
  if (typeof lng === 'number' && isFinite(lng)) fields.lng = { doubleValue: lng };
  await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields })
  }).catch(() => {});
}

async function obtenerUsuario(accessToken, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return null;
  const doc = await resp.json();
  const f = doc.fields || {};
  return {
    uid,
    nombre: f.nombre?.stringValue || '',
    fcmToken: f.fcmToken?.stringValue || null,
    grupoFamiliarId: f.grupoFamiliarId?.stringValue || null,
    recibirAlertasFamilia: f.recibirAlertasFamilia?.booleanValue !== false
  };
}

// Devuelve todos los usuarios cuyo grupoFamiliarId sea el indicado (los "hijos" vinculados)
async function listarIntegrantesGrupo(accessToken, grupoId) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'usuarios' }],
      where: {
        fieldFilter: {
          field: { fieldPath: 'grupoFamiliarId' },
          op: 'EQUAL',
          value: { stringValue: grupoId }
        }
      },
      limit: 50
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
      const uid = doc.name.split('/').pop();
      const f = doc.fields || {};
      return {
        uid,
        nombre: f.nombre?.stringValue || '',
        fcmToken: f.fcmToken?.stringValue || null,
        recibirAlertasFamilia: f.recibirAlertasFamilia?.booleanValue !== false
      };
    });
}

async function enviarPush(accessToken, token, titulo, cuerpo) {
  const resp = await fetch(`https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: {
        token,
        notification: { title: titulo, body: cuerpo },
        webpush: { notification: { icon: '/icon-192.png' }, fcm_options: { link: '/' } }
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

  const { idToken, email, lat, lng } = req.body || {};
  if (!idToken) {
    res.status(400).json({ error: 'Falta idToken' });
    return;
  }

  try {
    const uid = await verificarUsuario(idToken);
    if (!uid) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }

    const accessToken = await obtenerAccessToken();
    const yo = await obtenerUsuario(accessToken, uid);
    if (!yo) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    // Si tengo grupoFamiliarId, el titular es ese uid; si no, yo mismo soy el titular.
    const grupoId = yo.grupoFamiliarId || uid;

    const integrantes = [];
    if (grupoId !== uid) {
      const titular = await obtenerUsuario(accessToken, grupoId);
      if (titular) integrantes.push(titular);
    }
    const hijos = await listarIntegrantesGrupo(accessToken, grupoId);
    integrantes.push(...hijos);

    // Solo se avisa a quienes tengan token push Y no hayan desactivado las
    // notificaciones familiares desde "Mi cuenta" (activadas por defecto).
    const destinatarios = integrantes.filter((p) => p.uid !== uid && p.fcmToken && p.recibirAlertasFamilia !== false);

    const nombre = yo.nombre || (email ? String(email).split('@')[0] : 'Un familiar');
    const mapsLink = (typeof lat === 'number' && isFinite(lat) && typeof lng === 'number' && isFinite(lng)) ? ` Ubicación: https://maps.google.com/?q=${lat},${lng}` : '';
    // Aviso dentro de la app para TODOS los familiares (aunque no tengan push activo)
    const mensajeAviso = `${nombre} activó el botón SOS`;
    for (const p of integrantes.filter((x) => x.uid !== uid)) {
      await crearAviso(accessToken, p.uid, mensajeAviso, email, lat, lng);
    }
    const resultados = [];
    for (const persona of destinatarios) {
      const r = await enviarPush(
        accessToken,
        persona.fcmToken,
        '🚨 Alerta familiar SOS',
        `${nombre}${email ? ' (' + email + ')' : ''} activó el botón de pánico.${mapsLink}`
      );
      resultados.push({ uid: persona.uid, ok: r.ok });
    }

    res.status(200).json({ ok: true, notificados: resultados.length, resultados });
  } catch (err) {
    console.error('Error notificando a la familia:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
