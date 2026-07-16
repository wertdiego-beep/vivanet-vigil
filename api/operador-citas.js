// Función serverless de Vercel: /api/operador-citas
// Devuelve, solo para la cuenta central (Diego), todas las visitas técnicas
// agendadas por los clientes (colección "citas" bajo cada usuario) junto con
// la lista de técnicos disponibles (usuarios con rolEmpresa === 'tecnico'),
// para poder asignar quién va a cada visita. Usa la cuenta de servicio para
// leer Firestore vía REST, sin depender de las reglas de seguridad del
// cliente (mismo patrón que /api/operador-datos).

import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
const CENTRAL_UID = 'ziDCZASJ7GaMoBhUDw7uPbKmFgE2';
// Operadores autorizados de la central. Se definen en Vercel con la variable
// OPERADORES_UIDS (uids separados por coma). Si no existe, queda solo la
// cuenta central original, así nada cambia hasta que agregues operadores.
const OPERADORES = (process.env.OPERADORES_UIDS || CENTRAL_UID).split(',').map((s) => s.trim()).filter(Boolean);
const esOperador = (uid) => !!uid && OPERADORES.includes(uid);
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

async function listarCitas(accessToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'citas', allDescendants: true }],
      limit: 200
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
        estado: f.estado?.stringValue || 'agendada',
        tecnicoUid: f.tecnicoUid?.stringValue || '',
        tecnicoNombre: f.tecnicoNombre?.stringValue || '',
        comentarioTecnico: f.comentarioTecnico?.stringValue || '',
        fotoBase64: f.fotoBase64?.stringValue || '',
        equipo: f.equipo?.stringValue || '',
        problema: f.problema?.stringValue || '',
        numeroTicket: f.numeroTicket?.stringValue || '',
        creadaEn: f.creadaEn?.timestampValue || null
      };
    })
    .sort((a, b) => new Date(b.creadaEn || 0) - new Date(a.creadaEn || 0));
}

async function obtenerCliente(accessToken, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return null;
  const doc = await resp.json();
  const f = doc.fields || {};
  return { nombre: f.nombre?.stringValue || '', local: f.local?.stringValue || '' };
}

async function listarTecnicos(accessToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'usuarios' }],
      where: {
        fieldFilter: {
          field: { fieldPath: 'rolEmpresa' },
          op: 'EQUAL',
          value: { stringValue: 'tecnico' }
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
      const uid = doc.name.split('/').pop();
      const f = doc.fields || {};
      return { uid, nombre: f.nombre?.stringValue || '' };
    });
}

async function obtenerNombreTecnico(accessToken, tecnicoUid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${tecnicoUid}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return '';
  const doc = await resp.json();
  return doc.fields?.nombre?.stringValue || '';
}

async function asignar(res, accessToken, { clienteUid, citaId, tecnicoUid }) {
  if (!clienteUid || !citaId || !tecnicoUid) {
    res.status(400).json({ error: 'Faltan datos' });
    return;
  }
  const tecnicoNombre = await obtenerNombreTecnico(accessToken, tecnicoUid);
  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/citas/${citaId}` +
    `?updateMask.fieldPaths=tecnicoUid&updateMask.fieldPaths=tecnicoNombre&updateMask.fieldPaths=estado`;
  const resp = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fields: {
        tecnicoUid: { stringValue: tecnicoUid },
        tecnicoNombre: { stringValue: tecnicoNombre },
        estado: { stringValue: 'asignada' }
      }
    })
  });
  if (!resp.ok) {
    const data = await resp.json();
    console.error('Error asignando técnico:', data);
    res.status(502).json({ error: 'No se pudo asignar el técnico' });
    return;
  }
  res.status(200).json({ ok: true });
}

// Cierra el ticket/visita directamente desde el panel de la central, sin
// depender de que el técnico complete el paso desde su celular (ej: si el
// trabajo se coordinó por teléfono, o la central quiere cerrarlo a mano).
async function cerrar(res, accessToken, { clienteUid, citaId }) {
  if (!clienteUid || !citaId) {
    res.status(400).json({ error: 'Faltan datos' });
    return;
  }
  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/citas/${citaId}` +
    `?updateMask.fieldPaths=estado&updateMask.fieldPaths=completadaEn`;
  const resp = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fields: {
        estado: { stringValue: 'completada' },
        completadaEn: { timestampValue: new Date().toISOString() }
      }
    })
  });
  if (!resp.ok) {
    const data = await resp.json();
    console.error('Error cerrando ticket:', data);
    res.status(502).json({ error: 'No se pudo cerrar el ticket' });
    return;
  }
  res.status(200).json({ ok: true });
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

    if (accion === 'asignar') {
      await asignar(res, accessToken, req.body || {});
      return;
    }

    if (accion === 'cerrar') {
      await cerrar(res, accessToken, req.body || {});
      return;
    }

    const [citas, tecnicos] = await Promise.all([listarCitas(accessToken), listarTecnicos(accessToken)]);

    const clientesCache = {};
    for (const c of citas) {
      if (!clientesCache[c.clienteUid]) {
        clientesCache[c.clienteUid] = await obtenerCliente(accessToken, c.clienteUid);
      }
      const info = clientesCache[c.clienteUid] || {};
      c.clienteNombre = info.nombre || '';
      c.clienteLocal = info.local || '';
    }

    res.status(200).json({ ok: true, citas, tecnicos });
  } catch (err) {
    console.error('Error en citas del operador:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
