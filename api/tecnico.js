// Función serverless de Vercel: /api/tecnico
// Combina en un solo endpoint lo que necesita el panel del técnico: listar
// sus visitas asignadas, marcarlas "en camino" y completarlas con comentario
// y foto (base64, ya comprimida en el navegador). Se combinó en un solo
// archivo (en vez de dos) para no superar el límite de 12 funciones
// serverless del plan gratuito de Vercel. Usa la cuenta de servicio para
// leer/escribir en Firestore vía REST, sin depender de las reglas de
// seguridad del cliente.

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
  if (!resp.ok) {
    const errText = await resp.text().catch(() => '');
    console.error('Error listando citas del técnico (Firestore):', resp.status, errText.slice(0, 500));
    return [];
  }
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
        equipo: f.equipo?.stringValue || '',
        problema: f.problema?.stringValue || '',
        fotoFalla: f.fotoFalla?.stringValue || '',
        numeroTicket: f.numeroTicket?.stringValue || ''
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

async function obtenerCita(accessToken, clienteUid, citaId) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/citas/${citaId}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return null;
  const doc = await resp.json();
  const f = doc.fields || {};
  return { tecnicoUid: f.tecnicoUid?.stringValue || '' };
}

async function listar(res, accessToken, uid) {
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
  const citasPropias = citas.filter((c) => ['asignada', 'en_camino', 'completada'].includes(c.estado));
  res.status(200).json({ ok: true, citas: citasPropias });
}

async function actualizar(res, accessToken, uid, { clienteUid, citaId, accion, comentario, fotoBase64 }) {
  if (!clienteUid || !citaId) {
    res.status(400).json({ error: 'Faltan datos de la visita' });
    return;
  }
  const cita = await obtenerCita(accessToken, clienteUid, citaId);
  if (!cita) {
    res.status(404).json({ error: 'Visita no encontrada' });
    return;
  }
  if (cita.tecnicoUid !== uid) {
    res.status(403).json({ error: 'Esta visita no está asignada a tu cuenta' });
    return;
  }

  const fieldPaths = ['estado'];
  const fields = {};

  if (accion === 'en_camino') {
    fields.estado = { stringValue: 'en_camino' };
  } else {
    fields.estado = { stringValue: 'completada' };
    fieldPaths.push('completadaEn');
    fields.completadaEn = { timestampValue: new Date().toISOString() };
    if (comentario) {
      fieldPaths.push('comentarioTecnico');
      fields.comentarioTecnico = { stringValue: String(comentario).slice(0, 2000) };
    }
    if (fotoBase64) {
      fieldPaths.push('fotoBase64');
      fields.fotoBase64 = { stringValue: fotoBase64 };
    }
  }

  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/citas/${citaId}` +
    `?` + fieldPaths.map((p) => `updateMask.fieldPaths=${p}`).join('&');
  const resp = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields })
  });
  if (!resp.ok) {
    const data = await resp.json();
    console.error('Error actualizando cita:', data);
    res.status(502).json({ error: 'No se pudo actualizar la visita' });
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
    const uid = await verificarUsuario(idToken);
    if (!uid) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }
    const accessToken = await obtenerAccessToken();

    if (!accion || accion === 'listar') {
      await listar(res, accessToken, uid);
    } else if (['en_camino', 'completar'].includes(accion)) {
      await actualizar(res, accessToken, uid, req.body || {});
    } else {
      res.status(400).json({ error: 'Acción no válida' });
    }
  } catch (err) {
    console.error('Error en panel técnico:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
