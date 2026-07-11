// Función serverless de Vercel: /api/tecnico-citas
// Devuelve las visitas técnicas (citas) que la central le asignó a quien
// llama, sin importar de qué cliente sean. Usa la cuenta de servicio para
// leer Firestore vía REST (collectionGroup query sobre "citas" filtrando por
// tecnicoUid), sin depender de las reglas de seguridad del cliente.

import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
const FIREBASE_API_KEY = 'AIzaSyCRAFZXVB6VZ8vAVoMF3WDvjcmUCiInP2g';

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
  const signature = signer.sign(privateKey).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const jwt = `${unsigned}.${signature}`;
  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt })
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error('No se pudo obtener el token de acceso: ' + JSON.stringify(data));
  return data.access_token;
}

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

async function listarCitasTecnico(accessToken, tecnicoUid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'citas', allDescendants: true }],
      where: {
        fieldFilter: {
          field: { fieldPath: 'tecnicoUid' },
          op: 'EQUAL',
          value: { stringValue: tecnicoUid }
        }
      },
      limit: 100
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
      const citaId = parts.pop();
      parts.pop(); // 'citas'
      const clienteUid = parts.pop();
      const f = doc.fields || {};
      return {
        clienteUid,
        citaId,
        fecha: f.fecha?.stringValue || '',
        horario: f.horario?.stringValue || '',
        estado: f.estado?.stringValue || 'agendada'
      };
    });
}

async function obtenerCliente(accessToken, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return null;
  const doc = await resp.json();
  const f = doc.fields || {};
  return {
    nombre: f.nombre?.stringValue || '',
    local: f.local?.stringValue || '',
    direccion: f.direccion?.stringValue || ''
  };
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }
  const { idToken } = req.body || {};
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
    const citas = await listarCitasTecnico(accessToken, uid);

    const clientesCache = {};
    for (const c of citas) {
      if (!clientesCache[c.clienteUid]) {
        clientesCache[c.clienteUid] = await obtenerCliente(accessToken, c.clienteUid);
      }
      const info = clientesCache[c.clienteUid] || {};
      c.clienteNombre = info.nombre || '';
      c.clienteLocal = info.local || '';
      c.clienteDireccion = info.direccion || '';
    }

    // Solo las asignadas/en camino/completadas, no las "agendadas" que aún no tienen técnico asignado.
    const citasPropias = citas.filter((c) => ['asignada', 'en_camino', 'completada'].includes(c.estado));

    res.status(200).json({ ok: true, citas: citasPropias });
  } catch (err) {
    console.error('Error en citas del técnico:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
