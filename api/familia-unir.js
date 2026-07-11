// Función serverless de Vercel: /api/familia-unir
// Permite que un usuario (ej: un hijo) se una al grupo familiar de otro
// usuario (ej: el padre que contrató el plan) usando un código corto.
// Verifica el idToken de quien llama contra Firebase Auth, busca al titular
// dueño del código vía la cuenta de servicio (sin depender de las reglas de
// seguridad del cliente, igual que los endpoints de operador), marca al que
// llama con grupoFamiliarId = uid del titular, y copia los contactos de
// emergencia del titular a la cuenta del que se une (una sola vez, al unirse).

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

// Verifica el idToken del que llama contra Firebase Auth y devuelve su UID (o null).
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

// Busca al titular dueño de un código de familia dado.
async function buscarTitularPorCodigo(accessToken, codigo) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'usuarios' }],
      where: {
        fieldFilter: {
          field: { fieldPath: 'codigoFamilia' },
          op: 'EQUAL',
          value: { stringValue: codigo }
        }
      },
      limit: 1
    }
  };
  const resp = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!resp.ok) return null;
  const data = await resp.json();
  const encontrado = (data || []).find((r) => r.document);
  if (!encontrado) return null;
  const doc = encontrado.document;
  const uid = doc.name.split('/').pop();
  const f = doc.fields || {};
  return {
    uid,
    nombre: f.nombre?.stringValue || '',
    local: f.local?.stringValue || ''
  };
}

async function listarContactos(accessToken, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}/contactos?pageSize=100`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return [];
  const data = await resp.json();
  const docs = data.documents || [];
  return docs.map((doc) => doc.fields || {});
}

function valorFirestore(v) {
  if (v === undefined || v === null) return { stringValue: '' };
  if (typeof v === 'boolean') return { booleanValue: v };
  return { stringValue: String(v) };
}

async function copiarContacto(accessToken, uidDestino, campos) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uidDestino}/contactos`;
  const fields = {
    nombre: valorFirestore(campos.nombre?.stringValue || ''),
    chatId: valorFirestore(campos.chatId?.stringValue || ''),
    telefono: valorFirestore(campos.telefono?.stringValue || ''),
    activo: { booleanValue: campos.activo?.booleanValue !== false }
  };
  await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields })
  });
}

async function marcarGrupoFamiliar(accessToken, uid, grupoFamiliarId) {
  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}` +
    `?updateMask.fieldPaths=grupoFamiliarId`;
  await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { grupoFamiliarId: { stringValue: grupoFamiliarId } } })
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }

  const { idToken, codigo } = req.body || {};
  if (!idToken || !codigo) {
    res.status(400).json({ error: 'Faltan datos (idToken o código)' });
    return;
  }

  try {
    const uid = await verificarUsuario(idToken);
    if (!uid) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }

    const accessToken = await obtenerAccessToken();
    const titular = await buscarTitularPorCodigo(accessToken, codigo.trim().toUpperCase());

    if (!titular) {
      res.status(404).json({ error: 'No encontramos ninguna familia con ese código' });
      return;
    }
    if (titular.uid === uid) {
      res.status(400).json({ error: 'Ese código es el tuyo propio' });
      return;
    }

    await marcarGrupoFamiliar(accessToken, uid, titular.uid);

    const contactos = await listarContactos(accessToken, titular.uid);
    for (const c of contactos) {
      await copiarContacto(accessToken, uid, c);
    }

    res.status(200).json({ ok: true, familiaNombre: titular.local || titular.nombre || 'la familia' });
  } catch (err) {
    console.error('Error uniendo a familia:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
