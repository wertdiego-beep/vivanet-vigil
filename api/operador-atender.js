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
    `?updateMask.fieldPaths=asignadaA&updateMask.fieldPaths=asignadaEn&updateMask.fieldPaths=estado`;
  const body = {
    fields: {
      asignadaA: { stringValue: operador || '' },
      asignadaEn: { timestampValue: new Date().toISOString() },
      estado: { stringValue: 'verificando' }
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
  const accionesSinAlerta = ['nota-cliente', 'reporte-estado', 'chat-listar', 'chat-enviar'];
  if (!idToken || !clienteUid || (!alertaId && !accionesSinAlerta.includes(accion))) {
    res.status(400).json({ error: 'Faltan datos (idToken, clienteUid o alertaId)' });
    return;
  }

  try {
    const uid = await verificarOperador(idToken);
    // Multitenant: el operador solo puede actuar sobre clientes de SU empresa.
    const accessTokenPre = await obtenerAccessToken();
    const [docOp, docCli] = await Promise.all([
      fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`, { headers: { Authorization: `Bearer ${accessTokenPre}` } }).then((r) => r.ok ? r.json() : {}),
      fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}`, { headers: { Authorization: `Bearer ${accessTokenPre}` } }).then((r) => r.ok ? r.json() : {})
    ]);
    // Autorizado si está en la lista clásica o si es operador de alguna empresa.
    if (!esOperador(uid) && !docOp.fields?.operadorDe?.stringValue) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }
    const empOp = docOp.fields?.operadorDe?.stringValue || docOp.fields?.empresaId?.stringValue || 'sos360-la-serena';
    // La plataforma puede quitarle a un operador el permiso de atender/cerrar alertas.
    if (docOp.fields?.permisosOp?.mapValue?.fields?.atender?.booleanValue === false) {
      res.status(403).json({ error: 'La plataforma desactivó tu permiso para atender alertas' });
      return;
    }
    const empCli = docCli.fields?.empresaId?.stringValue || 'sos360-la-serena';
    if (empOp !== empCli) {
      res.status(403).json({ error: 'Este cliente pertenece a otra empresa de seguridad' });
      return;
    }

    const accessToken = accessTokenPre; // reutiliza el token ya obtenido
    if (accion === 'nota-cliente') {
      // Nota fija de la central sobre el cliente ("perro bravo", "porton trasero").
      const urlNota =
        `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}` +
        `?updateMask.fieldPaths=notaCentral`;
      const respNota = await fetch(urlNota, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { notaCentral: { stringValue: (nota || '').slice(0, 500) } } })
      });
      res.status(200).json({ ok: respNota.ok });
      return;
    }
    if (accion === 'reporte-estado') {
      // Marcar un reporte de incidente como revisado (o pendiente).
      const repId = (req.body.reporteId || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(repId)) { res.status(400).json({ error: 'Reporte no válido' }); return; }
      await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/reportes/${repId}?updateMask.fieldPaths=estado&updateMask.fieldPaths=revisadoPor`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { estado: { stringValue: req.body.estado === 'pendiente' ? 'pendiente' : 'revisado' }, revisadoPor: { stringValue: operador || '' } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'chat-listar') {
      // Mensajes del chat central-cliente (espec. 22).
      const docs = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/chatCentral?pageSize=60`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const mensajes = (docs.documents || []).map((d) => ({
        de: d.fields?.de?.stringValue || 'cliente',
        texto: d.fields?.texto?.stringValue || '',
        foto: d.fields?.foto?.stringValue || null,
        creadaEn: d.fields?.creadaEn?.timestampValue || null
      })).sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0)).slice(-40);
      res.status(200).json({ ok: true, mensajes });
      return;
    }
    if (accion === 'chat-enviar') {
      const texto = (req.body.texto || '').trim().slice(0, 500);
      if (!texto) { res.status(400).json({ error: 'Mensaje vacío' }); return; }
      await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${clienteUid}/chatCentral`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { de: { stringValue: 'central' }, texto: { stringValue: texto }, operador: { stringValue: operador || '' }, creadaEn: { timestampValue: new Date().toISOString() } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
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
