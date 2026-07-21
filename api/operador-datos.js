// Función serverless de Vercel: /api/operador-datos
// Devuelve, solo para la cuenta central (Diego), la lista de clientes y las
// alertas SOS activas de todos ellos. Verifica primero el idToken del que
// llama contra Firebase Auth (accounts:lookup) y confirma que su UID sea el
// de la central; si no, responde 403. Luego usa la cuenta de servicio para
// leer Firestore vía REST, sin depender de las reglas de seguridad del
// cliente (igual que /api/send-push).

import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
const CENTRAL_UID = 'ziDCZASJ7GaMoBhUDw7uPbKmFgE2'; // cuenta de Diego (central)
// Operadores autorizados de la central. Se definen en Vercel con la variable
// OPERADORES_UIDS (uids separados por coma). Si no existe, queda solo la
// cuenta central original, así nada cambia hasta que agregues operadores.
const OPERADORES = (process.env.OPERADORES_UIDS || CENTRAL_UID).split(',').map((s) => s.trim()).filter(Boolean);
const esOperador = (uid) => !!uid && OPERADORES.includes(uid);
// Nivel 1 de la plataforma: los superadmins (nosotros). Por defecto, la cuenta central.
const SUPERADMINS = (process.env.SUPERADMIN_UIDS || CENTRAL_UID).split(',').map((s) => s.trim()).filter(Boolean);
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
    scope: 'https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/identitytoolkit',
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

// Verifica el idToken del que llama contra Firebase Auth y devuelve su UID
// (o null si no es válido). No usamos firebase-admin: llamamos directo a la
// API REST de Identity Toolkit con la clave pública del proyecto.
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

async function listarClientes(accessToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios?pageSize=300`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) return [];
  const data = await resp.json();
  const docs = data.documents || [];
  return docs
    .map((doc) => {
      const id = doc.name.split('/').pop();
      const f = doc.fields || {};
      return {
        uid: id,
        nombre: f.nombre?.stringValue || '',
        local: f.local?.stringValue || '',
        direccion: f.direccion?.stringValue || '',
        telefono: f.telefono?.stringValue || '',
        notaCentral: f.notaCentral?.stringValue || '',
        modo: f.modo?.stringValue || 'empresa',
        rolEmpresa: f.rolEmpresa?.stringValue || '',
        grupoFamiliarId: f.grupoFamiliarId?.stringValue || '',
        ultimaSenal: f.ultimaSenal?.timestampValue || f.ultimaSenal?.stringValue || null,
        operadorDe: f.operadorDe?.stringValue || '',
        tipoMovil: f.tipoMovil?.stringValue || '',
        especialidad: f.especialidad?.stringValue || '',
        grupoId: f.grupoId?.stringValue || '',
        cargoMunicipal: f.cargoMunicipal?.stringValue || '',
        // Multitenant: usuarios sin empresa pertenecen a la empresa original.
        empresaId: f.empresaId?.stringValue || 'sos360-la-serena'
      };
    })
    .filter((c) => !esOperador(c.uid));
}

// IMPORTANTE: antes las alertas activas se pedían con una consulta filtrada
// (where estado == 'activa') sobre el grupo de colecciones "alertas". Ese
// tipo de consulta requiere un índice de grupo de colecciones en Firestore
// que este proyecto no tiene, así que Firestore respondía con error, el
// código lo tragaba con "return []" y el panel SIEMPRE mostraba 0 alertas
// activas (aunque el historial —que usa la consulta SIN filtro— sí las
// mostraba). Ahora las activas se derivan en JS desde esa misma consulta
// sin filtro, que no necesita ningún índice.
function derivarAlertasActivas(alertasRecientes) {
  // Una alerta "activa" con más de 12 horas se considera vencida (quedó
  // huérfana de alguna prueba o de un cierre que falló) y no se muestra
  // como emergencia vigente.
  const corte = Date.now() - 12 * 3600 * 1000;
  return alertasRecientes
    .filter((a) => (a.estado === 'activa' || a.estado === 'verificando') && a.creadaEn && new Date(a.creadaEn).getTime() >= corte)
    .slice(0, 50);
}

// Trae hasta 120 alertas recientes (de cualquier estado, de cualquier
// cliente) sin filtro, para armar el historial general y las estadísticas.
// Antes traía 300, pero como este endpoint se consulta en cada actualización
// del panel operador, ese límite alto multiplicaba mucho las lecturas de
// Firestore y agotaba la cuota gratuita diaria. 120 alcanza para el
// historial visible (20), las estadísticas del día y las alertas activas.
// No usamos "where"/"orderBy" combinados para evitar depender de un índice
// compuesto en Firestore; ordenamos y filtramos acá mismo, en JS.
async function listarAlertasRecientes(accessToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`;
  const body = {
    structuredQuery: {
      from: [{ collectionId: 'alertas', allDescendants: true }],
      limit: 120
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
      const alertaId = parts.pop();
      parts.pop(); // 'alertas'
      const uid = parts.pop();
      const f = doc.fields || {};
      const ubic = f.ubicacion?.mapValue?.fields;
      return {
        clienteUid: uid,
        alertaId,
        estado: f.estado?.stringValue || '',
        creadaEn: f.creadaEn?.timestampValue || null,
        atendidaEn: f.atendidaEn?.timestampValue || null,
        canceladaEn: f.canceladaEn?.timestampValue || null,
        resultado: f.resultado?.stringValue || '',
        notaAtencion: f.notaAtencion?.stringValue || '',
        atendidaPor: f.atendidaPor?.stringValue || '',
        asignadaA: f.asignadaA?.stringValue || '',
        movilAsignado: f.movilAsignado?.stringValue || '',
        movilNombre: f.movilNombre?.stringValue || '',
        movilEstado: f.movilEstado?.stringValue || '',
        movilReporteNota: f.movilReporteNota?.stringValue || '',
        movilReporteFoto: f.movilReporteFoto?.stringValue || '',
        ubicacion: ubic
          ? {
              lat: parseFloat(ubic.lat?.doubleValue ?? ubic.lat?.integerValue ?? 0),
              lng: parseFloat(ubic.lng?.doubleValue ?? ubic.lng?.integerValue ?? 0),
              precision: parseFloat(ubic.precision?.doubleValue ?? ubic.precision?.integerValue ?? 0)
            }
          : null
      };
    })
    .sort((a, b) => new Date(b.creadaEn || 0) - new Date(a.creadaEn || 0));
}

// Obtiene el código de equipo de la central (Diego) vía la cuenta de
// servicio, generándolo y guardándolo si todavía no existe. Se hace acá (en
// vez de con el SDK del cliente) porque las reglas de seguridad de Firestore
// no le permiten a la cuenta central escribir su propio documento desde el
// navegador, por lo que un .set() directo desde el cliente fallaba en
// silencio y mostraba un código que nunca quedaba realmente guardado.
async function obtenerOGenerarCodigoOperador(accessToken, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/usuarios/${uid}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (resp.ok) {
    const doc = await resp.json();
    const codigoExistente = doc.fields?.codigoFamilia?.stringValue;
    if (codigoExistente) return { codigo: codigoExistente, creado: false };
  }
  const codigo = uid.slice(0, 6).toUpperCase();
  const patchUrl = `${url}?updateMask.fieldPaths=codigoFamilia`;
  const patchResp = await fetch(patchUrl, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields: { codigoFamilia: { stringValue: codigo } } })
  });
  if (!patchResp.ok) {
    const errData = await patchResp.json().catch(() => ({}));
    throw new Error('No se pudo guardar el código: ' + (errData.error?.message || patchResp.status));
  }
  return { codigo, creado: true };
}

function calcularStats(alertasRecientes) {
  const hoy = new Date();
  hoy.setHours(0, 0, 0, 0);
  const alertasHoy = alertasRecientes.filter((a) => a.creadaEn && new Date(a.creadaEn) >= hoy).length;

  const tiempos = alertasRecientes
    .filter((a) => a.creadaEn && a.atendidaEn)
    .map((a) => (new Date(a.atendidaEn) - new Date(a.creadaEn)) / 60000)
    .filter((min) => min >= 0 && min < 24 * 60);

  const tiempoPromedioResp = tiempos.length
    ? Math.round((tiempos.reduce((a, b) => a + b, 0) / tiempos.length) * 10) / 10
    : null;

  return { alertasHoy, tiempoPromedioResp };
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
    const accessToken = await obtenerAccessToken();
    const base0 = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

    // Multitenant: perfil del solicitante para saber su empresa y su rol.
    const perfilOp = await fetch(`${base0}/usuarios/${uid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
    // Superadmins: los de la variable de Vercel + los designados desde el panel.
    const docSA = await fetch(`${base0}/plataforma/superadmins`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
    const saExtra = (docSA.fields?.uids?.arrayValue?.values || []).map((v) => v.stringValue);
    const CUENTA_MAESTRA = SUPERADMINS[0];
    const esSA = SUPERADMINS.includes(uid) || saExtra.includes(uid);
    const esOp = esOperador(uid) || !!perfilOp.fields?.operadorDe?.stringValue;

    // ── Acciones de plataforma (solo superadmin: nosotros, el nivel superior) ──
    if (accion && accion.startsWith('sa-')) {
      if (!esSA) { res.status(403).json({ error: 'Solo la plataforma puede hacer esto' }); return; }
      const base = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;
      if (accion === 'sa-empresas') {
        const [respEmp, clientes] = await Promise.all([
          fetch(`${base}/empresas?pageSize=200`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {}),
          listarClientes(accessToken)
        ]);
        const conteo = {};
        clientes.forEach((c) => { conteo[c.empresaId] = (conteo[c.empresaId] || 0) + 1; });
        const empresas = (respEmp.documents || []).map((d) => ({
          id: d.name.split('/').pop(),
          nombre: d.fields?.nombre?.stringValue || d.name.split('/').pop(),
          estado: d.fields?.estado?.stringValue || 'activa',
          clientes: 0
        }));
        if (!empresas.find((e) => e.id === 'sos360-la-serena')) {
          empresas.unshift({ id: 'sos360-la-serena', nombre: 'SOS360 La Serena (nuestra)', estado: 'activa', clientes: 0 });
        }
        empresas.forEach((e) => { e.clientes = conteo[e.id] || 0; });
        res.status(200).json({ ok: true, empresas });
        return;
      }
      if (accion === 'sa-crear-empresa') {
        const nombre = (req.body.empresaNombre || '').trim();
        if (!nombre) { res.status(400).json({ error: 'Falta el nombre de la empresa' }); return; }
        const slug = nombre.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
        await fetch(`${base}/empresas/${slug}?updateMask.fieldPaths=nombre&updateMask.fieldPaths=estado&updateMask.fieldPaths=creadaEn`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { nombre: { stringValue: nombre }, estado: { stringValue: 'activa' }, creadaEn: { timestampValue: new Date().toISOString() } } })
        });
        res.status(200).json({ ok: true, id: slug });
        return;
      }
      if (accion === 'sa-toggle-empresa') {
        const empId = (req.body.empresaIdDestino || '').trim();
        if (!empId || empId === 'sos360-la-serena') { res.status(400).json({ error: 'Esa empresa no se puede suspender' }); return; }
        const doc = await fetch(`${base}/empresas/${empId}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const nuevo = (doc.fields?.estado?.stringValue === 'suspendida') ? 'activa' : 'suspendida';
        await fetch(`${base}/empresas/${empId}?updateMask.fieldPaths=estado`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { estado: { stringValue: nuevo } } })
        });
        res.status(200).json({ ok: true, estado: nuevo });
        return;
      }
      if (accion === 'sa-asignar-operador') {
        const email = (req.body.operadorEmail || '').trim().toLowerCase();
        const empId = (req.body.empresaIdDestino || '').trim();
        if (!email || !empId) { res.status(400).json({ error: 'Faltan email o empresa' }); return; }
        const lookup = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/accounts:lookup`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: [email] })
        }).then((r) => r.json());
        const cuenta = lookup.users && lookup.users[0];
        if (!cuenta) { res.status(404).json({ error: 'No existe una cuenta con ese correo. La persona debe crear su cuenta primero.' }); return; }
        await fetch(`${base}/usuarios/${cuenta.localId}?updateMask.fieldPaths=operadorDe&updateMask.fieldPaths=empresaId`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { operadorDe: { stringValue: empId }, empresaId: { stringValue: empId } } })
        });
        res.status(200).json({ ok: true, uid: cuenta.localId });
        return;
      }
      if (accion === 'sa-categorias') {
        // Categorías de reportes configurables por la plataforma (espec. 31/38).
        if (req.body.modo === 'set') {
          const json = JSON.stringify(req.body.categorias || []).slice(0, 4000);
          await fetch(`${base}/plataforma/categorias?updateMask.fieldPaths=json`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ fields: { json: { stringValue: json } } })
          });
          res.status(200).json({ ok: true });
          return;
        }
        const doc = await fetch(`${base}/plataforma/categorias`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        let categorias = [];
        try { categorias = JSON.parse(doc.fields?.json?.stringValue || '[]'); } catch (e) {}
        res.status(200).json({ ok: true, categorias });
        return;
      }
      if (accion === 'sa-funciones') {
        // Funciones POR EMPRESA (el plan que le asignas a cada cliente que te contrata).
        const empId = (req.body.empresaIdFn || 'sos360-la-serena').trim();
        const docPath = empId === 'sos360-la-serena' ? `${base}/plataforma/funciones` : `${base}/empresas/${empId}`;
        if (req.body.modo === 'set') {
          const p = req.body.funciones || {};
          const fields = {};
          Object.keys(p).forEach((k) => { fields[k] = { booleanValue: !!p[k] }; });
          await fetch(`${docPath}?updateMask.fieldPaths=${empId === 'sos360-la-serena' ? 'flags' : 'funciones'}`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ fields: { [empId === 'sos360-la-serena' ? 'flags' : 'funciones']: { mapValue: { fields } } } })
          });
          res.status(200).json({ ok: true });
          return;
        }
        const doc = await fetch(docPath, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const fraw = doc.fields?.[empId === 'sos360-la-serena' ? 'flags' : 'funciones']?.mapValue?.fields || {};
        const funciones = {};
        Object.keys(fraw).forEach((k) => { funciones[k] = fraw[k].booleanValue !== false; });
        res.status(200).json({ ok: true, funciones });
        return;
      }
      if (accion === 'sa-superadmin') {
        // Designar o quitar mando máximo. Solo la cuenta maestra puede.
        if (uid !== CUENTA_MAESTRA) { res.status(403).json({ error: 'Solo la cuenta maestra puede nombrar superadmins.' }); return; }
        const destino = (req.body.operadorUid || '').trim();
        if (!/^[A-Za-z0-9]+$/.test(destino)) { res.status(400).json({ error: 'Operador no válido' }); return; }
        let uids = saExtra.slice();
        if (req.body.quitar) uids = uids.filter((x) => x !== destino);
        else if (!uids.includes(destino)) uids.push(destino);
        await fetch(`${base0}/plataforma/superadmins?updateMask.fieldPaths=uids`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { uids: { arrayValue: { values: uids.map((x) => ({ stringValue: x })) } } } })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'sa-operadores') {
        // Lista de TODOS los operadores de la plataforma con sus permisos.
        const resp = await fetch(`${base}/usuarios?pageSize=300`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const docs = resp.documents || [];
        const ops = docs.filter((d) => {
          const id = d.name.split('/').pop();
          return OPERADORES.includes(id) || !!d.fields?.operadorDe?.stringValue;
        }).map((d) => {
          const id = d.name.split('/').pop();
          const praw = d.fields?.permisosOp?.mapValue?.fields || {};
          const permisos = { atender: true, clientes: true, historial: true, tecnico: true, exportar: true, zonas: true, credenciales: true, moviles: true, asistencia: true, operativos: true, encurso: true, registro: true, llamados: true, tickets: true };
          Object.keys(praw).forEach((k) => { permisos[k] = praw[k].booleanValue !== false; });
          return {
            uid: id,
            nombre: d.fields?.nombre?.stringValue || '',
            empresa: d.fields?.operadorDe?.stringValue || d.fields?.empresaId?.stringValue || 'sos360-la-serena',
            esSuperadmin: SUPERADMINS.includes(id) || saExtra.includes(id),
          esMaestra: id === CUENTA_MAESTRA,
            permisos
          };
        });
        // Correos de esas cuentas (para mostrarlos)
        try {
          const lk = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/accounts:lookup`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ localId: ops.map((o) => o.uid) })
          }).then((r) => r.json());
          (lk.users || []).forEach((u) => { const o = ops.find((x) => x.uid === u.localId); if (o) o.email = u.email || ''; });
        } catch (e) {}
        res.status(200).json({ ok: true, operadores: ops });
        return;
      }
      if (accion === 'sa-permisos') {
        // Cambiar los permisos de un operador (directo por uid).
        if (req.body.operadorUid && req.body.modo === 'set') {
          const p = req.body.permisos || {};
          const fields = {};
          Object.keys(p).forEach((k) => { fields[k] = { booleanValue: !!p[k] }; });
          await fetch(`${base}/usuarios/${req.body.operadorUid}?updateMask.fieldPaths=permisosOp`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ fields: { permisosOp: { mapValue: { fields } } } })
          });
          res.status(200).json({ ok: true });
          return;
        }
        const email = (req.body.operadorEmail || '').trim().toLowerCase();
        if (!email) { res.status(400).json({ error: 'Falta el correo del operador' }); return; }
        const lookup = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/accounts:lookup`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: [email] })
        }).then((r) => r.json());
        const cuenta = lookup.users && lookup.users[0];
        if (!cuenta) { res.status(404).json({ error: 'No existe una cuenta con ese correo.' }); return; }
        const docU = await fetch(`${base}/usuarios/${cuenta.localId}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const esOpDestino = OPERADORES.includes(cuenta.localId) || !!docU.fields?.operadorDe?.stringValue;
        if (!esOpDestino) { res.status(400).json({ error: 'Esa cuenta no es operador de ninguna central.' }); return; }
        if (req.body.modo === 'set') {
          const p = req.body.permisos || {};
          const fields = {};
          Object.keys(p).forEach((k) => { fields[k] = { booleanValue: !!p[k] }; });
          await fetch(`${base}/usuarios/${cuenta.localId}?updateMask.fieldPaths=permisosOp`, {
            method: 'PATCH',
            headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ fields: { permisosOp: { mapValue: { fields } } } })
          });
          res.status(200).json({ ok: true });
          return;
        }
        const praw = docU.fields?.permisosOp?.mapValue?.fields || {};
        const permisosDest = { atender: true, clientes: true, historial: true, tecnico: true, exportar: true, zonas: true, credenciales: true, moviles: true, asistencia: true, operativos: true, encurso: true, registro: true, llamados: true, tickets: true };
        Object.keys(praw).forEach((k) => { permisosDest[k] = praw[k].booleanValue !== false; });
        res.status(200).json({ ok: true, permisos: permisosDest, empresa: docU.fields?.operadorDe?.stringValue || docU.fields?.empresaId?.stringValue || 'sos360-la-serena' });
        return;
      }
      if (accion === 'sa-credenciales') {
        // Registro global de credenciales creadas (solo nivel superior). Sin claves en texto.
        const q = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ structuredQuery: { from: [{ collectionId: 'credenciales' }], limit: 300 } })
        }).then((r) => r.json());
        let creds = (q || []).filter((x) => x.document).map((x) => {
          const f = x.document.fields || {};
          return {
            uid: x.document.name.split('/').pop(),
            email: f.email?.stringValue || '', nombre: f.nombre?.stringValue || '',
            rol: f.rol?.stringValue || '', empresaId: f.empresaId?.stringValue || '',
            esOperador: f.esOperador?.booleanValue === true,
            claveLargo: Number(f.claveLargo?.integerValue || 0),
            clave: f.clave?.stringValue || '',
            creadoPorNombre: f.creadoPorNombre?.stringValue || '',
            creadoEn: f.creadoEn?.timestampValue || null
          };
        });
        let empresasNom = {};
        try {
          const es = await fetch(`${base}/empresas?pageSize=200`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.json());
          (es.documents || []).forEach((d) => { empresasNom[d.name.split('/').pop()] = d.fields?.nombre?.stringValue || ''; });
        } catch (e) {}
        creds.forEach((c) => { c.empresaNombre = empresasNom[c.empresaId] || c.empresaId; });
        creds.sort((a, b) => new Date(b.creadoEn || 0) - new Date(a.creadoEn || 0));
        res.status(200).json({ ok: true, credenciales: creds });
        return;
      }
      res.status(400).json({ error: 'Acción de plataforma desconocida' });
      return;
    }

    // ── Acciones del MÓVIL DE REACCIÓN (rol 'movil'; no es operador de central) ──
    const _accMovil = ['movil-recorrido', 'movil-parada', 'movil-despachos', 'movil-estado', 'movil-reporte', 'movil-incidente', 'movil-contactos', 'movil-chat-listar', 'movil-chat-enviar', 'movil-misiones', 'movil-mision-estado', 'movil-mision-reporte'];
    if (_accMovil.includes(accion)) {
      const miRolM = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolM !== 'movil') { res.status(403).json({ error: 'Solo un móvil de reacción puede usar esto.' }); return; }
      const empMovil = perfilOp.fields?.empresaId?.stringValue || 'sos360-la-serena';
      const rutaRec = `${base0}/empresas/${empMovil}/recorridos/${uid}`;
      const hoyStr = new Date().toISOString().slice(0, 10);

      if (accion === 'movil-recorrido') {
        const doc = await fetch(rutaRec, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const fecha = doc.fields?.fecha?.stringValue || '';
        const paradasRaw = (fecha === hoyStr) ? (doc.fields?.paradas?.arrayValue?.values || []) : [];
        const paradas = paradasRaw.map((p) => {
          const pf = p.mapValue?.fields || {};
          return { clienteUid: pf.clienteUid?.stringValue || '', nombre: pf.nombre?.stringValue || '', direccion: pf.direccion?.stringValue || '', lat: pf.lat ? parseFloat(pf.lat.doubleValue ?? pf.lat.integerValue ?? 0) : null, lng: pf.lng ? parseFloat(pf.lng.doubleValue ?? pf.lng.integerValue ?? 0) : null, nota: pf.nota?.stringValue || '', foto: pf.foto?.stringValue || '', estado: pf.estado?.stringValue || 'pendiente', visitadaEn: pf.visitadaEn?.stringValue || '' };
        });
        res.status(200).json({ ok: true, fecha: hoyStr, paradas });
        return;
      }
      if (accion === 'movil-parada') {
        // Marca una parada del recorrido como visitada, con nota/foto opcional.
        const idx = parseInt(req.body.idx, 10);
        const doc = await fetch(rutaRec, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const arr = (doc.fields?.paradas?.arrayValue?.values || []).slice();
        if (isNaN(idx) || idx < 0 || idx >= arr.length) { res.status(400).json({ error: 'Parada no válida' }); return; }
        const pf = arr[idx].mapValue.fields;
        pf.estado = { stringValue: req.body.estado === 'pendiente' ? 'pendiente' : 'visitada' };
        if (req.body.nota != null) pf.nota = { stringValue: String(req.body.nota).slice(0, 500) };
        if (req.body.foto) pf.foto = { stringValue: String(req.body.foto).slice(0, 900000) };
        pf.visitadaEn = { stringValue: new Date().toISOString() };
        await fetch(`${rutaRec}?updateMask.fieldPaths=paradas`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { paradas: { arrayValue: { values: arr } } } })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'movil-despachos') {
        // SOS asignados a este móvil (de cualquier cliente de su empresa).
        const [lista, clientes] = await Promise.all([listarAlertasRecientes(accessToken), listarClientes(accessToken)]);
        const infoCli = {};
        clientes.forEach((c) => { infoCli[c.uid] = c; });
        const mios = lista.filter((a) => a.movilAsignado === uid && a.movilEstado && !['resuelto', 'falsa'].includes(a.movilEstado));
        const despachos = mios.map((a) => {
          const c = infoCli[a.clienteUid] || {};
          return { clienteUid: a.clienteUid, alertaId: a.alertaId, cliente: c.local || c.nombre || 'Cliente', direccion: c.direccion || '', telefono: c.telefono || '', notaCentral: c.notaCentral || '', movilEstado: a.movilEstado, creadaEn: a.creadaEn, ubicacion: a.ubicacion };
        });
        res.status(200).json({ ok: true, despachos });
        return;
      }
      if (accion === 'movil-estado') {
        const cUid = (req.body.clienteUid || '').trim();
        const aId = (req.body.alertaId || '').trim();
        const est = ['despachado', 'en_camino', 'en_sitio', 'resuelto', 'falsa'].includes(req.body.movilEstado) ? req.body.movilEstado : '';
        if (!/^[A-Za-z0-9]+$/.test(cUid) || !/^[A-Za-z0-9]+$/.test(aId) || !est) { res.status(400).json({ error: 'Datos no válidos' }); return; }
        await fetch(`${base0}/usuarios/${cUid}/alertas/${aId}?updateMask.fieldPaths=movilEstado&updateMask.fieldPaths=movilEstadoEn`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { movilEstado: { stringValue: est }, movilEstadoEn: { timestampValue: new Date().toISOString() } } })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'movil-misiones') {
        // Misiones activas asignadas a este móvil.
        const docs = await fetch(`${base0}/empresas/${empMovil}/misiones?pageSize=100`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const misiones = (docs.documents || []).map((dd) => ({
          id: dd.name.split('/').pop(),
          movilUid: dd.fields?.movilUid?.stringValue || '',
          titulo: dd.fields?.titulo?.stringValue || '',
          descripcion: dd.fields?.descripcion?.stringValue || '',
          direccion: dd.fields?.direccion?.stringValue || '',
          lat: dd.fields?.lat ? parseFloat(dd.fields.lat.doubleValue ?? dd.fields.lat.integerValue) : null,
          lng: dd.fields?.lng ? parseFloat(dd.fields.lng.doubleValue ?? dd.fields.lng.integerValue) : null,
          tipo: dd.fields?.tipo?.stringValue || 'patrullaje',
          estado: dd.fields?.estado?.stringValue || 'despachado',
          creadaEn: dd.fields?.creadaEn?.timestampValue || null
        })).filter((m) => m.movilUid === uid && m.estado !== 'resuelto' && m.estado !== 'cerrada')
          .sort((a, b) => new Date(b.creadaEn || 0) - new Date(a.creadaEn || 0));
        res.status(200).json({ ok: true, misiones });
        return;
      }
      if (accion === 'movil-mision-estado') {
        const mid = (req.body.misionId || '').trim();
        const est = ['en_camino', 'en_sitio', 'resuelto'].includes(req.body.estado) ? req.body.estado : '';
        if (!/^[A-Za-z0-9]+$/.test(mid) || !est) { res.status(400).json({ error: 'Datos no válidos' }); return; }
        const docM = await fetch(`${base0}/empresas/${empMovil}/misiones/${mid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        if ((docM.fields?.movilUid?.stringValue || '') !== uid) { res.status(403).json({ error: 'Ese operativo no es tuyo.' }); return; }
        await fetch(`${base0}/empresas/${empMovil}/misiones/${mid}?updateMask.fieldPaths=estado&updateMask.fieldPaths=estadoEn`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { estado: { stringValue: est }, estadoEn: { timestampValue: new Date().toISOString() } } })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'movil-mision-reporte') {
        // Reporte de situación desde terreno: texto + foto. Se pueden enviar varios.
        const mid = (req.body.misionId || '').trim();
        if (!/^[A-Za-z0-9]+$/.test(mid)) { res.status(400).json({ error: 'Operativo no válido' }); return; }
        const docM = await fetch(`${base0}/empresas/${empMovil}/misiones/${mid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        if ((docM.fields?.movilUid?.stringValue || '') !== uid) { res.status(403).json({ error: 'Ese operativo no es tuyo.' }); return; }
        const texto = String(req.body.texto || '').trim().slice(0, 800);
        const foto = req.body.foto ? String(req.body.foto).slice(0, 900000) : null;
        if (!texto && !foto) { res.status(400).json({ error: 'Envía al menos un texto o una foto.' }); return; }
        const fields = { texto: { stringValue: texto }, creadaEn: { timestampValue: new Date().toISOString() } };
        if (foto) fields.foto = { stringValue: foto };
        await fetch(`${base0}/empresas/${empMovil}/misiones/${mid}/reportes`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'movil-contactos') {
        // Teléfonos de la central (empresa) y del jefe/gerente de seguridad.
        const [empDoc, todos] = await Promise.all([
          fetch(`${base0}/empresas/${empMovil}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {}),
          listarClientes(accessToken)
        ]);
        const jefe = todos.find((c) => c.empresaId === empMovil && c.rolEmpresa === 'jefe') || todos.find((c) => c.empresaId === empMovil && c.rolEmpresa === 'gerente');
        res.status(200).json({ ok: true,
          central: { nombre: empDoc.fields?.nombre?.stringValue || 'Central', telefono: empDoc.fields?.telefono?.stringValue || '' },
          jefe: jefe ? { nombre: jefe.nombre || 'Jefe de seguridad', telefono: jefe.telefono || '' } : null
        });
        return;
      }
      if (accion === 'movil-chat-listar') {
        const col = req.body.canal === 'jefe' ? 'chatJefe' : 'chatCentral';
        const docs = await fetch(`${base0}/usuarios/${uid}/${col}?pageSize=60`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const mensajes = (docs.documents || []).map((dd) => ({
          de: dd.fields?.de?.stringValue || '', texto: dd.fields?.texto?.stringValue || '',
          foto: dd.fields?.foto?.stringValue || null, creadaEn: dd.fields?.creadaEn?.timestampValue || null
        })).sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0)).slice(-40);
        res.status(200).json({ ok: true, mensajes });
        return;
      }
      if (accion === 'movil-chat-enviar') {
        const col = req.body.canal === 'jefe' ? 'chatJefe' : 'chatCentral';
        const texto = String(req.body.texto || '').trim().slice(0, 500);
        const foto = req.body.foto ? String(req.body.foto).slice(0, 900000) : null;
        if (!texto && !foto) { res.status(400).json({ error: 'Mensaje vacío' }); return; }
        const fields = { de: { stringValue: 'movil' }, texto: { stringValue: texto }, creadaEn: { timestampValue: new Date().toISOString() } };
        if (foto) fields.foto = { stringValue: foto };
        await fetch(`${base0}/usuarios/${uid}/${col}`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'movil-incidente') {
        // El móvil reporta un incidente ocurrido durante su recorrido.
        const fields = {
          categoria: { stringValue: '🚐 Incidente en recorrido' },
          icono: { stringValue: '🚐' },
          texto: { stringValue: String(req.body.texto || '').slice(0, 800) },
          estado: { stringValue: 'pendiente' },
          anonimo: { booleanValue: false },
          creadaEn: { timestampValue: new Date().toISOString() }
        };
        if (req.body.foto) fields.foto = { stringValue: String(req.body.foto).slice(0, 900000) };
        await fetch(`${base0}/usuarios/${uid}/reportes`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'movil-reporte') {
        const cUid = (req.body.clienteUid || '').trim();
        const aId = (req.body.alertaId || '').trim();
        if (!/^[A-Za-z0-9]+$/.test(cUid) || !/^[A-Za-z0-9]+$/.test(aId)) { res.status(400).json({ error: 'Datos no válidos' }); return; }
        const fields = { movilReporteEn: { timestampValue: new Date().toISOString() } };
        if (req.body.nota != null) fields.movilReporteNota = { stringValue: String(req.body.nota).slice(0, 800) };
        if (req.body.foto) fields.movilReporteFoto = { stringValue: String(req.body.foto).slice(0, 900000) };
        await fetch(`${base0}/usuarios/${cUid}/alertas/${aId}?` + Object.keys(fields).map((k) => `updateMask.fieldPaths=${k}`).join('&'), {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields })
        });
        res.status(200).json({ ok: true });
        return;
      }
    }

    // ── ASISTENCIA del personal (cualquier rol de empresa; no requiere ser operador) ──
    if (accion === 'asist-mi-config' || accion === 'asist-marcar') {
      const rolA = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!rolA) { res.status(403).json({ error: 'No tienes un cargo en una empresa.' }); return; }
      const empA = perfilOp.fields?.empresaId?.stringValue || 'sos360-la-serena';
      // Función activable desde el panel superior: si está cortada, no hay asistencia.
      const rutaFnA = empA === 'sos360-la-serena' ? `${base0}/plataforma/funciones` : `${base0}/empresas/${empA}`;
      const docFnA = await fetch(rutaFnA, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const frawA = (docFnA.fields?.flags || docFnA.fields?.funciones)?.mapValue?.fields || {};
      if (frawA.asistencia?.booleanValue === false) { res.status(403).json({ error: 'La función de asistencia no está activada para tu empresa.' }); return; }
      // Fecha y hora locales de Chile (America/Santiago).
      const pf = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Santiago', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(new Date());
      const gp = (t) => (pf.find((x) => x.type === t) || {}).value;
      const fechaCl = `${gp('year')}-${gp('month')}-${gp('day')}`;
      const horaCl = `${gp('hour')}:${gp('minute')}`;
      const cfg = {
        lat: perfilOp.fields?.asistLat ? parseFloat(perfilOp.fields.asistLat.doubleValue ?? perfilOp.fields.asistLat.integerValue) : null,
        lng: perfilOp.fields?.asistLng ? parseFloat(perfilOp.fields.asistLng.doubleValue ?? perfilOp.fields.asistLng.integerValue) : null,
        lugar: perfilOp.fields?.asistLugar?.stringValue || '',
        entrada: perfilOp.fields?.asistEntrada?.stringValue || '',
        salida: perfilOp.fields?.asistSalida?.stringValue || '',
        bloqueo: perfilOp.fields?.asistBloqueo?.booleanValue === true
      };
      const regRuta = `${base0}/empresas/${empA}/asistencia/${uid}_${fechaCl}`;
      if (accion === 'asist-mi-config') {
        const reg = await fetch(regRuta, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        res.status(200).json({ ok: true, config: cfg, hoy: {
          fecha: fechaCl,
          entradaHora: reg.fields?.entradaHora?.stringValue || null,
          atrasoMin: reg.fields?.atrasoMin ? parseInt(reg.fields.atrasoMin.integerValue) : null,
          salidaHora: reg.fields?.salidaHora?.stringValue || null,
          jornadaOk: reg.fields?.jornadaOk?.booleanValue ?? null
        } });
        return;
      }
      // asist-marcar
      if (cfg.lat == null || cfg.lng == null) { res.status(400).json({ error: 'Tu jefe aún no te asigna un punto de trabajo.' }); return; }
      const la = Number(req.body.lat), lo = Number(req.body.lng);
      if (isNaN(la) || isNaN(lo)) { res.status(400).json({ error: 'Sin ubicación GPS.' }); return; }
      const R = 6371000, rad = Math.PI / 180;
      const dLat = (cfg.lat - la) * rad, dLng = (cfg.lng - lo) * rad;
      const hx = Math.sin(dLat / 2) ** 2 + Math.cos(la * rad) * Math.cos(cfg.lat * rad) * Math.sin(dLng / 2) ** 2;
      const dist = Math.round(2 * R * Math.asin(Math.sqrt(hx)));
      if (dist > 200) { res.status(400).json({ error: `Estás a ${dist} m de tu punto de trabajo. Debes estar a menos de 200 m para marcar.` }); return; }
      const aMin = (h) => { const [hh, mm] = String(h || '0:0').split(':').map(Number); return hh * 60 + (mm || 0); };
      const tipo = req.body.tipo === 'salida' ? 'salida' : 'entrada';
      const fields = { uid: { stringValue: uid }, nombre: { stringValue: perfilOp.fields?.nombre?.stringValue || '' }, fecha: { stringValue: fechaCl } };
      let masks = ['uid', 'nombre', 'fecha'];
      if (tipo === 'entrada') {
        const atraso = cfg.entrada ? Math.max(0, aMin(horaCl) - aMin(cfg.entrada)) : 0;
        fields.entradaHora = { stringValue: horaCl };
        fields.entradaEn = { timestampValue: new Date().toISOString() };
        fields.atrasoMin = { integerValue: String(atraso) };
        masks = masks.concat(['entradaHora', 'entradaEn', 'atrasoMin']);
      } else {
        const jornadaOk = cfg.salida ? (aMin(horaCl) >= aMin(cfg.salida)) : true;
        fields.salidaHora = { stringValue: horaCl };
        fields.salidaEn = { timestampValue: new Date().toISOString() };
        fields.jornadaOk = { booleanValue: jornadaOk };
        masks = masks.concat(['salidaHora', 'salidaEn', 'jornadaOk']);
      }
      await fetch(regRuta + '?' + masks.map((k) => `updateMask.fieldPaths=${k}`).join('&'), {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields })
      });
      res.status(200).json({ ok: true, tipo, hora: horaCl, dist });
      return;
    }

    if (!esOp) {
      res.status(403).json({ error: 'No autorizado' });
      return;
    }
    const empresaOperador = perfilOp.fields?.operadorDe?.stringValue || perfilOp.fields?.empresaId?.stringValue || 'sos360-la-serena';

    // Empresa suspendida por la plataforma: su central deja de operar.
    if (empresaOperador !== 'sos360-la-serena') {
      const docEmp = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/empresas/${empresaOperador}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (docEmp.fields?.estado?.stringValue === 'suspendida') {
        res.status(403).json({ error: 'Tu empresa está suspendida por la plataforma' });
        return;
      }
    }

    if (accion === 'emp-crear') {
      // El jefe/gerente crea una cuenta de empleado a mano (correo + clave).
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe' && miRol !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente puede crear empleados.' }); return; }
      const email = (req.body.email || '').trim().toLowerCase();
      const pass = (req.body.pass || '').trim();
      const nombre = (req.body.nombre || '').trim();
      const rol = ['jefe','gerente','empleado','tecnico','supervisor','guardia','movil'].includes(req.body.rol) ? req.body.rol : 'empleado';
      const tel = (req.body.telefono || '').trim();
      if (!email || !/.+@.+\..+/.test(email)) { res.status(400).json({ error: 'Correo no válido' }); return; }
      if (pass.length < 6) { res.status(400).json({ error: 'La clave debe tener al menos 6 caracteres' }); return; }
      if (!nombre) { res.status(400).json({ error: 'Falta el nombre' }); return; }
      // El superadmin puede crear la cuenta en cualquier empresa (la elegida en su panel).
      const empDest = (esSA && /^[a-z0-9-]+$/.test(req.body.empresaIdDestino || '')) ? req.body.empresaIdDestino : empresaOperador;
      // Crear la cuenta en Firebase Auth.
      const su = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${FIREBASE_API_KEY}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pass, returnSecureToken: false })
      }).then((r) => r.json());
      if (!su.localId) { res.status(400).json({ error: su.error?.message === 'EMAIL_EXISTS' ? 'Ya existe una cuenta con ese correo.' : 'No se pudo crear la cuenta.' }); return; }
      // Guardar su ficha en la empresa del jefe.
      const fields = {
        nombre: { stringValue: nombre }, telefono: { stringValue: tel },
        empresaId: { stringValue: empDest }, rolEmpresa: { stringValue: rol },
        modo: { stringValue: 'empresa' }, creadoManual: { booleanValue: true }
      };
      if (req.body.esOperador) fields.operadorDe = { stringValue: empDest };
      if (req.body.especialidad) fields.especialidad = { stringValue: String(req.body.especialidad).slice(0, 40) };
      await fetch(`${base0}/usuarios/${su.localId}?` + Object.keys(fields).map((k) => `updateMask.fieldPaths=${k}`).join('&'), {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields })
      });
      // Registro de credencial (auditoria). Por SEGURIDAD no se guarda la clave en texto:
      // solo el evento (correo, cargo, quien la creo y cuando) + el largo de la clave.
      try {
        const miNombreC = perfilOp.fields?.nombre?.stringValue || perfilOp.fields?.displayName?.stringValue || '';
        await fetch(`${base0}/credenciales/${su.localId}?` + ['email','nombre','rol','empresaId','esOperador','claveLargo','clave','creadoPorUid','creadoPorNombre','creadoEn'].map((k)=>`updateMask.fieldPaths=${k}`).join('&'), {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: {
            email: { stringValue: email }, nombre: { stringValue: nombre }, rol: { stringValue: rol },
            empresaId: { stringValue: empDest }, esOperador: { booleanValue: !!req.body.esOperador },
            claveLargo: { integerValue: String(pass.length) },
            clave: { stringValue: pass },
            creadoPorUid: { stringValue: uid }, creadoPorNombre: { stringValue: miNombreC },
            creadoEn: { timestampValue: new Date().toISOString() }
          } })
        });
      } catch (e) {}
      res.status(200).json({ ok: true, uid: su.localId });
      return;
    }
    if (accion === 'emp-credenciales') {
      // Registro de cuentas creadas. sa-* = todas (solo nivel superior); emp-* = solo la propia empresa (jefe/gerente).
      const miRolC = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolC !== 'jefe' && miRolC !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente ve este registro.' }); return; }
      const prawC = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawC.credenciales?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso al registro de credenciales.' }); return; }
      const q = await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ structuredQuery: { from: [{ collectionId: 'credenciales' }], limit: 300 } })
      }).then((r) => r.json());
      let creds = (q || []).filter((x) => x.document).map((x) => {
        const f = x.document.fields || {};
        return {
          uid: x.document.name.split('/').pop(),
          email: f.email?.stringValue || '', nombre: f.nombre?.stringValue || '',
          rol: f.rol?.stringValue || '', empresaId: f.empresaId?.stringValue || '',
          esOperador: f.esOperador?.booleanValue === true,
          claveLargo: Number(f.claveLargo?.integerValue || 0),
          clave: f.clave?.stringValue || '',
          creadoPorNombre: f.creadoPorNombre?.stringValue || '',
          creadoEn: f.creadoEn?.timestampValue || null
        };
      });
      creds = creds.filter((c) => c.empresaId === empresaOperador);
      creds.sort((a, b) => new Date(b.creadoEn || 0) - new Date(a.creadoEn || 0));
      res.status(200).json({ ok: true, credenciales: creds });
      return;
    }
    if (accion === 'emp-quitar') {
      // Quita a la persona del equipo: sin rol, sin empresa, sin operador.
      // NO destruye su cuenta (reversible): solo la desvincula de la empresa.
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe' && miRol !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente puede quitar personal.' }); return; }
      const destino = (req.body.personalUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(destino) || destino === uid) { res.status(400).json({ error: destino === uid ? 'No puedes quitarte a ti mismo.' : 'Persona no válida' }); return; }
      const docD = await fetch(`${base0}/usuarios/${destino}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docD.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
      await fetch(`${base0}/usuarios/${destino}?updateMask.fieldPaths=rolEmpresa&updateMask.fieldPaths=operadorDe&updateMask.fieldPaths=empresaId`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { rolEmpresa: { stringValue: '' }, operadorDe: { stringValue: '' }, empresaId: { stringValue: 'sin-empresa' } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'emp-editar') {
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe' && miRol !== 'gerente') { res.status(403).json({ error: 'No autorizado' }); return; }
      const destino = (req.body.personalUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(destino)) { res.status(400).json({ error: 'Persona no válida' }); return; }
      const docD = await fetch(`${base0}/usuarios/${destino}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docD.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
      const fields = {};
      if (req.body.nombre != null) fields.nombre = { stringValue: String(req.body.nombre).trim() };
      if (req.body.telefono != null) fields.telefono = { stringValue: String(req.body.telefono).trim() };
      if (req.body.rol && ['jefe','gerente','empleado','tecnico','supervisor','guardia','movil'].includes(req.body.rol)) fields.rolEmpresa = { stringValue: req.body.rol };
      if (!Object.keys(fields).length) { res.status(400).json({ error: 'Nada que cambiar' }); return; }
      await fetch(`${base0}/usuarios/${destino}?` + Object.keys(fields).map((k) => `updateMask.fieldPaths=${k}`).join('&'), {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'emp-reset-clave') {
      // El jefe/gerente (o SA) le pone una clave nueva a alguien y queda reflejada en el registro.
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe' && miRol !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente puede restablecer claves.' }); return; }
      const prawR = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawR.credenciales?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso al registro de credenciales.' }); return; }
      const destino = (req.body.personalUid || '').trim();
      const pass = (req.body.pass || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(destino)) { res.status(400).json({ error: 'Persona no válida' }); return; }
      if (pass.length < 6) { res.status(400).json({ error: 'La clave debe tener al menos 6 caracteres.' }); return; }
      const docD = await fetch(`${base0}/usuarios/${destino}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docD.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
      // Cambiar la clave en Firebase Auth (endpoint de administración).
      const up = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/accounts:update`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ localId: destino, password: pass })
      }).then((r) => r.json());
      if (up.error) { res.status(400).json({ error: 'No se pudo cambiar la clave.' }); return; }
      // Reflejar la nueva clave en el registro de credenciales.
      try {
        const miNombreR = perfilOp.fields?.nombre?.stringValue || perfilOp.fields?.displayName?.stringValue || '';
        await fetch(`${base0}/credenciales/${destino}?` + ['clave','claveLargo','reseteadoPor','reseteadoEn'].map((k) => `updateMask.fieldPaths=${k}`).join('&'), {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: {
            clave: { stringValue: pass }, claveLargo: { integerValue: String(pass.length) },
            reseteadoPor: { stringValue: miNombreR }, reseteadoEn: { timestampValue: new Date().toISOString() }
          } })
        });
      } catch (e) {}
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'emp-roles-permisos') {
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe') { res.status(403).json({ error: 'Solo el jefe define los permisos por rol.' }); return; }
      const KEYS = ['atender','clientes','historial','tecnico','exportar','zonas','credenciales','moviles','asistencia','operativos','encurso','registro','llamados','tickets'];
      const ROLES = ['gerente','supervisor','guardia','empleado','tecnico'];
      const empDoc = await fetch(`${base0}/empresas/${empresaOperador}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const rpRaw = empDoc.fields?.rolesPermisos?.mapValue?.fields || {};
      const roles = {};
      ROLES.forEach((r) => { const fr = rpRaw[r]?.mapValue?.fields || {}; const p = {}; KEYS.forEach((k) => { p[k] = fr[k]?.booleanValue !== false; }); roles[r] = p; });
      // Roles personalizados que creó el jefe.
      const rcRaw = empDoc.fields?.rolesCustom?.arrayValue?.values || [];
      const rolesCustom = rcRaw.map((rv) => { const rf = rv.mapValue?.fields || {}; const p = {}; const pf = rf.permisos?.mapValue?.fields || {}; KEYS.forEach((k) => { p[k] = pf[k]?.booleanValue !== false; }); return { id: rf.id?.stringValue || '', nombre: rf.nombre?.stringValue || '', permisos: p }; });
      res.status(200).json({ ok: true, roles, rolesCustom });
      return;
    }
    if (accion === 'emp-rolcustom-crear' || accion === 'emp-rolcustom-eliminar' || accion === 'emp-rolcustom-permiso') {
      const miRolRC = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolRC !== 'jefe') { res.status(403).json({ error: 'Solo el jefe crea roles personalizados.' }); return; }
      const KEYSRC = ['atender','clientes','historial','tecnico','exportar','zonas','credenciales','moviles','asistencia','operativos','encurso','registro','llamados','tickets'];
      const rutaERC = `${base0}/empresas/${empresaOperador}`;
      const docERC = await fetch(rutaERC, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      let lista = docERC.fields?.rolesCustom?.arrayValue?.values || [];

      if (accion === 'emp-rolcustom-crear') {
        const nombreRC = String(req.body.nombre || '').trim().slice(0, 50);
        if (!nombreRC) { res.status(400).json({ error: 'Ponle un nombre al rol.' }); return; }
        if (lista.length >= 20) { res.status(400).json({ error: 'Llegaste al máximo de roles personalizados.' }); return; }
        const idRC = 'rc_' + Date.now().toString(36);
        const pf = {}; KEYSRC.forEach((k) => { pf[k] = { booleanValue: true }; });
        lista.push({ mapValue: { fields: { id: { stringValue: idRC }, nombre: { stringValue: nombreRC }, permisos: { mapValue: { fields: pf } } } } });
      } else if (accion === 'emp-rolcustom-eliminar') {
        const idRC = String(req.body.rolId || '');
        lista = lista.filter((rv) => (rv.mapValue?.fields?.id?.stringValue || '') !== idRC);
      } else if (accion === 'emp-rolcustom-permiso') {
        const idRC = String(req.body.rolId || '');
        const keyRC = String(req.body.key || '');
        if (!KEYSRC.includes(keyRC)) { res.status(400).json({ error: 'Permiso no válido' }); return; }
        const onRC = req.body.on !== false;
        lista = lista.map((rv) => {
          const rf = rv.mapValue?.fields || {};
          if ((rf.id?.stringValue || '') !== idRC) return rv;
          const pf = rf.permisos?.mapValue?.fields || {};
          const pf2 = {}; KEYSRC.forEach((k) => { pf2[k] = { booleanValue: (k === keyRC) ? onRC : (pf[k]?.booleanValue !== false) }; });
          return { mapValue: { fields: { id: rf.id, nombre: rf.nombre, permisos: { mapValue: { fields: pf2 } } } } };
        });
      }
      await fetch(`${rutaERC}?updateMask.fieldPaths=rolesCustom`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { rolesCustom: { arrayValue: { values: lista } } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'emp-roles-permisos-set') {
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe') { res.status(403).json({ error: 'Solo el jefe define los permisos por rol.' }); return; }
      const KEYS = ['atender','clientes','historial','tecnico','exportar','zonas','credenciales','moviles','asistencia','operativos','encurso','registro','llamados','tickets'];
      const ROLES = ['gerente','supervisor','guardia','empleado','tecnico'];
      const rolD = (req.body.rol || '').trim();
      const key = (req.body.key || '').trim();
      if (!ROLES.includes(rolD) || !KEYS.includes(key)) { res.status(400).json({ error: 'Datos no válidos' }); return; }
      const on = req.body.on !== false;
      const empDoc = await fetch(`${base0}/empresas/${empresaOperador}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const rpRaw = empDoc.fields?.rolesPermisos?.mapValue?.fields || {};
      const rolesOut = {};
      ROLES.forEach((r) => {
        const fr = rpRaw[r]?.mapValue?.fields || {};
        const pf = {};
        KEYS.forEach((k) => { let v = fr[k]?.booleanValue !== false; if (r === rolD && k === key) v = on; pf[k] = { booleanValue: v }; });
        rolesOut[r] = { mapValue: { fields: pf } };
      });
      await fetch(`${base0}/empresas/${empresaOperador}?updateMask.fieldPaths=rolesPermisos`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { rolesPermisos: { mapValue: { fields: rolesOut } } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'moviles-empresa') {
      // Lista los móviles de reacción de la empresa del operador (para despachar / armar recorrido).
      const clientes = await listarClientes(accessToken);
      const moviles = clientes.filter((c) => c.empresaId === empresaOperador && c.rolEmpresa === 'movil')
        .map((c) => ({ uid: c.uid, nombre: c.nombre || c.local || 'Móvil', telefono: c.telefono || '', tipo: c.tipoMovil || 'patrullaje' }));
      res.status(200).json({ ok: true, moviles });
      return;
    }
    if (accion === 'asist-config-set') {
      const miRolAs = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolAs !== 'jefe' && miRolAs !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente asigna puntos de trabajo.' }); return; }
      const prawAS = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawAS.asistencia?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la asistencia.' }); return; }
      if (!esSA) {
        const rutaFnP = empresaOperador === 'sos360-la-serena' ? `${base0}/plataforma/funciones` : `${base0}/empresas/${empresaOperador}`;
        const docFnP = await fetch(rutaFnP, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const frawP = (docFnP.fields?.flags || docFnP.fields?.funciones)?.mapValue?.fields || {};
        if (frawP.asistencia?.booleanValue === false) { res.status(403).json({ error: 'La función de asistencia no está activada para tu empresa.' }); return; }
      }
      const destino = (req.body.personalUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(destino)) { res.status(400).json({ error: 'Persona no válida' }); return; }
      const docD = await fetch(`${base0}/usuarios/${destino}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docD.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
      const fields = {
        asistLat: { doubleValue: Number(req.body.lat) }, asistLng: { doubleValue: Number(req.body.lng) },
        asistLugar: { stringValue: String(req.body.lugar || '').slice(0, 120) },
        asistEntrada: { stringValue: String(req.body.entrada || '') }, asistSalida: { stringValue: String(req.body.salida || '') },
        asistBloqueo: { booleanValue: req.body.bloqueo === true }
      };
      await fetch(`${base0}/usuarios/${destino}?` + Object.keys(fields).map((k) => `updateMask.fieldPaths=${k}`).join('&'), {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'asist-listar') {
      const miRolAs = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolAs !== 'jefe' && miRolAs !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente ve la asistencia.' }); return; }
      const empAsist = (esSA && /^[a-z0-9-]+$/.test(req.body.empresaIdA || '')) ? req.body.empresaIdA : empresaOperador;
      const prawAS = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawAS.asistencia?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la asistencia.' }); return; }
      if (!esSA) {
        const rutaFnP = empresaOperador === 'sos360-la-serena' ? `${base0}/plataforma/funciones` : `${base0}/empresas/${empresaOperador}`;
        const docFnP = await fetch(rutaFnP, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const frawP = (docFnP.fields?.flags || docFnP.fields?.funciones)?.mapValue?.fields || {};
        if (frawP.asistencia?.booleanValue === false) { res.status(403).json({ error: 'La función de asistencia no está activada para tu empresa.' }); return; }
      }
      const pf2 = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Santiago', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
      const fecha = /^\d{4}-\d{2}-\d{2}$/.test(req.body.fecha || '') ? req.body.fecha : pf2;
      const [todos, regs] = await Promise.all([
        listarClientes(accessToken),
        fetch(`${base0}/empresas/${empAsist}/asistencia?pageSize=300`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {})
      ]);
      const regPor = {};
      (regs.documents || []).forEach((dd) => {
        if (dd.fields?.fecha?.stringValue !== fecha) return;
        regPor[dd.fields?.uid?.stringValue || ''] = {
          entradaHora: dd.fields?.entradaHora?.stringValue || null,
          atrasoMin: dd.fields?.atrasoMin ? parseInt(dd.fields.atrasoMin.integerValue) : null,
          salidaHora: dd.fields?.salidaHora?.stringValue || null,
          jornadaOk: dd.fields?.jornadaOk?.booleanValue ?? null
        };
      });
      const docsAll = await fetch(`${base0}/usuarios?pageSize=300`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const cfgPor = {};
      (docsAll.documents || []).forEach((dd) => {
        const id2 = dd.name.split('/').pop();
        cfgPor[id2] = {
          lat: dd.fields?.asistLat ? parseFloat(dd.fields.asistLat.doubleValue ?? dd.fields.asistLat.integerValue) : null,
          lng: dd.fields?.asistLng ? parseFloat(dd.fields.asistLng.doubleValue ?? dd.fields.asistLng.integerValue) : null,
          lugar: dd.fields?.asistLugar?.stringValue || '', entrada: dd.fields?.asistEntrada?.stringValue || '', salida: dd.fields?.asistSalida?.stringValue || '',
          bloqueo: dd.fields?.asistBloqueo?.booleanValue === true
        };
      });
      const personal = todos.filter((c) => c.empresaId === empAsist && c.rolEmpresa)
        .map((c) => ({ uid: c.uid, nombre: c.nombre || 'Sin nombre', rol: c.rolEmpresa, config: cfgPor[c.uid] || {}, registro: regPor[c.uid] || null }));
      res.status(200).json({ ok: true, fecha, personal });
      return;
    }
    if (accion === 'chat-movil-listar' || accion === 'chat-movil-enviar') {
      // Chat del panel con un móvil. El canal depende del rol:
      // jefe/gerente -> chatJefe · operadores de central -> chatCentral.
      const prawCM = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawCM.moviles?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la gestión de móviles.' }); return; }
      const mUid = (req.body.movilUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(mUid)) { res.status(400).json({ error: 'Móvil no válido' }); return; }
      const docM = await fetch(`${base0}/usuarios/${mUid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docM.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Ese móvil es de otra empresa.' }); return; }
      const miRolC2 = perfilOp.fields?.rolEmpresa?.stringValue || '';
      const esJefatura = miRolC2 === 'jefe' || miRolC2 === 'gerente';
      const col = esJefatura ? 'chatJefe' : 'chatCentral';
      if (accion === 'chat-movil-listar') {
        const docs = await fetch(`${base0}/usuarios/${mUid}/${col}?pageSize=60`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        const mensajes = (docs.documents || []).map((dd) => ({
          de: dd.fields?.de?.stringValue || '', texto: dd.fields?.texto?.stringValue || '',
          foto: dd.fields?.foto?.stringValue || null, creadaEn: dd.fields?.creadaEn?.timestampValue || null
        })).sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0)).slice(-40);
        res.status(200).json({ ok: true, mensajes, canal: col });
        return;
      }
      const texto = String(req.body.texto || '').trim().slice(0, 500);
      const foto = req.body.foto ? String(req.body.foto).slice(0, 900000) : null;
      if (!texto && !foto) { res.status(400).json({ error: 'Mensaje vacío' }); return; }
      const fields = { de: { stringValue: esJefatura ? 'jefe' : 'central' }, texto: { stringValue: texto }, creadaEn: { timestampValue: new Date().toISOString() } };
      if (foto) fields.foto = { stringValue: foto };
      await fetch(`${base0}/usuarios/${mUid}/${col}`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'movil-tipo') {
      // Asignar el TIPO de un móvil (salud, reparaciones, rescate, patrullaje, ayuda).
      const prawT = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawT.moviles?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la gestión de móviles.' }); return; }
      const mUid = (req.body.movilUid || '').trim();
      const tipo = ['salud', 'reparaciones', 'rescate', 'patrullaje', 'ayuda'].includes(req.body.tipo) ? req.body.tipo : 'patrullaje';
      if (!/^[A-Za-z0-9]+$/.test(mUid)) { res.status(400).json({ error: 'Móvil no válido' }); return; }
      const docMv = await fetch(`${base0}/usuarios/${mUid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docMv.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Ese móvil es de otra empresa.' }); return; }
      await fetch(`${base0}/usuarios/${mUid}?updateMask.fieldPaths=tipoMovil`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { tipoMovil: { stringValue: tipo } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'informe-dia') {
      // Informe operativo del día: todo lo importante de la empresa, ordenado.
      const fchI = (iso) => iso ? new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Santiago', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(iso)) : '';
      const hoyI = fchI(new Date().toISOString());
      const fechaI = /^\d{4}-\d{2}-\d{2}$/.test(req.body.fecha || '') ? req.body.fecha : hoyI;
      const [clientesTodosI, alertasTodasI, misDocsI, repsQI, asisDocsI] = await Promise.all([
        listarClientes(accessToken),
        listarAlertasRecientes(accessToken),
        fetch(`${base0}/empresas/${empresaOperador}/misiones?pageSize=100`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {}),
        fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ structuredQuery: { from: [{ collectionId: 'reportes', allDescendants: true }], limit: 100 } })
        }).then((r) => r.ok ? r.json() : []),
        fetch(`${base0}/empresas/${empresaOperador}/asistencia?pageSize=300`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {})
      ]);
      const miosI = new Set(clientesTodosI.filter((c) => c.empresaId === empresaOperador).map((c) => c.uid));
      const nombreDeI = {};
      clientesTodosI.forEach((c) => { nombreDeI[c.uid] = c.local || c.nombre || 'Cliente'; });
      // 1) Operativos despachados ese día (con descripción, resultado y reportes de terreno).
      const opsDia = (misDocsI.documents || []).filter((dd) => fchI(dd.fields?.creadaEn?.timestampValue) === fechaI).map((dd) => ({
        id: dd.name.split('/').pop(),
        titulo: dd.fields?.titulo?.stringValue || '', descripcion: dd.fields?.descripcion?.stringValue || '',
        movilNombre: dd.fields?.movilNombre?.stringValue || '', tipo: dd.fields?.tipo?.stringValue || '',
        direccion: dd.fields?.direccion?.stringValue || '', estado: dd.fields?.estado?.stringValue || '',
        creadaEn: dd.fields?.creadaEn?.timestampValue || null, creadaPor: dd.fields?.creadaPor?.stringValue || '',
        resultado: dd.fields?.resultado?.stringValue || '', cerradaPor: dd.fields?.cerradaPor?.stringValue || ''
      })).sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0));
      for (const m of opsDia.slice(0, 15)) {
        try {
          const rp = await fetch(`${base0}/empresas/${empresaOperador}/misiones/${m.id}/reportes?pageSize=30`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
          m.reportes = (rp.documents || []).map((rr) => ({ texto: rr.fields?.texto?.stringValue || '', foto: rr.fields?.foto?.stringValue || null, creadaEn: rr.fields?.creadaEn?.timestampValue || null })).sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0));
        } catch (e) { m.reportes = []; }
      }
      // 2) Alarmas SOS del día de la empresa.
      const sosDia = alertasTodasI.filter((a) => miosI.has(a.clienteUid) && fchI(a.creadaEn) === fechaI).map((a) => ({
        creadaEn: a.creadaEn, cliente: nombreDeI[a.clienteUid] || 'Cliente', estado: a.estado,
        resultado: a.resultado || '', atendidaPor: a.atendidaPor || '', nota: a.notaAtencion || '',
        movilNombre: a.movilNombre || '', movilEstado: a.movilEstado || ''
      })).sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0));
      // 3) Reportes de clientes e incidentes de recorrido del día.
      const repsDia = (repsQI || []).filter((r) => r.document).map((r) => {
        const parts = r.document.name.split('/'); parts.pop(); parts.pop();
        const cuid = parts.pop(); const ff = r.document.fields || {};
        return { clienteUid: cuid, cliente: ff.anonimo?.booleanValue === true ? 'Anónimo' : (nombreDeI[cuid] || 'Cliente'), categoria: ff.categoria?.stringValue || 'Otro', icono: ff.icono?.stringValue || '📌', texto: ff.texto?.stringValue || '', foto: ff.foto?.stringValue || null, estado: ff.estado?.stringValue || 'pendiente', creadaEn: ff.creadaEn?.timestampValue || null };
      }).filter((x) => miosI.has(x.clienteUid) && fchI(x.creadaEn) === fechaI)
        .sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0));
      // 4) Asistencia del día.
      const asisDia = (asisDocsI.documents || []).filter((dd) => dd.fields?.fecha?.stringValue === fechaI).map((dd) => ({
        nombre: nombreDeI[dd.fields?.uid?.stringValue || ''] || 'Trabajador/a',
        entradaHora: dd.fields?.entradaHora?.stringValue || null,
        atrasoMin: dd.fields?.atrasoMin ? parseInt(dd.fields.atrasoMin.integerValue) : null,
        salidaHora: dd.fields?.salidaHora?.stringValue || null,
        jornadaOk: dd.fields?.jornadaOk?.booleanValue ?? null
      })).sort((a, b) => (a.entradaHora || '99').localeCompare(b.entradaHora || '99'));
      res.status(200).json({ ok: true, fecha: fechaI, operativos: opsDia, sos: sosDia, reportes: repsDia, asistencia: asisDia });
      return;
    }
    if (accion === 'mision-crear') {
      // La central despacha un móvil con una MISIÓN: objetivo + descripción + lugar.
      const prawMi = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawMi.moviles?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la gestión de móviles.' }); return; }
      if (!esSA && prawMi.operativos?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso al despacho de operativos.' }); return; }
      const mUid = (req.body.movilUid || '').trim();
      const titulo = String(req.body.titulo || '').trim().slice(0, 120);
      const descripcion = String(req.body.descripcion || '').trim().slice(0, 600);
      if (!/^[A-Za-z0-9]+$/.test(mUid) || !titulo) { res.status(400).json({ error: 'Faltan el móvil o el objetivo del operativo.' }); return; }
      const docMv = await fetch(`${base0}/usuarios/${mUid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docMv.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Ese móvil es de otra empresa.' }); return; }
      const fields = {
        movilUid: { stringValue: mUid },
        movilNombre: { stringValue: docMv.fields?.nombre?.stringValue || 'Móvil' },
        tipo: { stringValue: docMv.fields?.tipoMovil?.stringValue || 'patrullaje' },
        titulo: { stringValue: titulo },
        descripcion: { stringValue: descripcion },
        direccion: { stringValue: String(req.body.direccion || '').slice(0, 200) },
        estado: { stringValue: 'despachado' },
        creadaEn: { timestampValue: new Date().toISOString() },
        creadaPor: { stringValue: perfilOp.fields?.nombre?.stringValue || '' }
      };
      if (req.body.lat != null && !isNaN(Number(req.body.lat))) { fields.lat = { doubleValue: Number(req.body.lat) }; fields.lng = { doubleValue: Number(req.body.lng) }; }
      const crea = await fetch(`${base0}/empresas/${empresaOperador}/misiones`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields })
      }).then((r) => r.json());
      res.status(200).json({ ok: true, misionId: (crea.name || '').split('/').pop() });
      return;
    }
    if (accion === 'mision-listar') {
      const prawMl = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawMl.moviles?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la gestión de móviles.' }); return; }
      if (!esSA && req.body.registro && prawMl.registro?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso al registro de operativos.' }); return; }
      if (!esSA && !req.body.registro && prawMl.encurso?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso al seguimiento de operativos.' }); return; }
      const docs = await fetch(`${base0}/empresas/${empresaOperador}/misiones?pageSize=100`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      let misiones = (docs.documents || []).map((dd) => ({
        id: dd.name.split('/').pop(),
        movilUid: dd.fields?.movilUid?.stringValue || '', movilNombre: dd.fields?.movilNombre?.stringValue || 'Móvil',
        tipo: dd.fields?.tipo?.stringValue || 'patrullaje',
        titulo: dd.fields?.titulo?.stringValue || '', descripcion: dd.fields?.descripcion?.stringValue || '',
        direccion: dd.fields?.direccion?.stringValue || '',
        estado: dd.fields?.estado?.stringValue || 'despachado',
        creadaEn: dd.fields?.creadaEn?.timestampValue || null,
        estadoEn: dd.fields?.estadoEn?.timestampValue || null,
        creadaPor: dd.fields?.creadaPor?.stringValue || '',
        resultado: dd.fields?.resultado?.stringValue || '',
        cerradaPor: dd.fields?.cerradaPor?.stringValue || '',
        cerradaEn: dd.fields?.cerradaEn?.timestampValue || null
      })).sort((a, b) => new Date(b.creadaEn || 0) - new Date(a.creadaEn || 0)).slice(0, req.body.registro ? 40 : 15);
      // Reportes de terreno de cada misión (texto + fotos).
      for (const m of misiones) {
        try {
          const rp = await fetch(`${base0}/empresas/${empresaOperador}/misiones/${m.id}/reportes?pageSize=30`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
          m.reportes = (rp.documents || []).map((rr) => ({
            texto: rr.fields?.texto?.stringValue || '', foto: rr.fields?.foto?.stringValue || null,
            creadaEn: rr.fields?.creadaEn?.timestampValue || null
          })).sort((a, b) => new Date(a.creadaEn || 0) - new Date(b.creadaEn || 0));
        } catch (e) { m.reportes = []; }
      }
      res.status(200).json({ ok: true, misiones });
      return;
    }
    if (accion === 'mision-cerrar') {
      const prawMc = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawMc.encurso?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso al seguimiento de operativos.' }); return; }
      const mid = (req.body.misionId || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(mid)) { res.status(400).json({ error: 'Operativo no válido' }); return; }
      const resultado = String(req.body.resultado || '').trim().slice(0, 600);
      const ahoraC = new Date().toISOString();
      await fetch(`${base0}/empresas/${empresaOperador}/misiones/${mid}?updateMask.fieldPaths=estado&updateMask.fieldPaths=estadoEn&updateMask.fieldPaths=resultado&updateMask.fieldPaths=cerradaPor&updateMask.fieldPaths=cerradaEn`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { estado: { stringValue: 'cerrada' }, estadoEn: { timestampValue: ahoraC }, resultado: { stringValue: resultado }, cerradaPor: { stringValue: perfilOp.fields?.nombre?.stringValue || '' }, cerradaEn: { timestampValue: ahoraC } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'ticket-crear') {
      // Toma de información de un llamado ciudadano → genera un ticket con folio.
      { const prTk = perfilOp.fields?.permisosOp?.mapValue?.fields || {}; if (!esSA && prTk.llamados?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la toma de llamados.' }); return; } }
      const b = req.body;
      const nombreT = String(b.nombre || '').trim().slice(0, 120);
      const categoriaT = String(b.categoria || '').trim().slice(0, 60);
      const descripcionT = String(b.descripcion || '').trim().slice(0, 1500);
      if (!nombreT || !categoriaT || !descripcionT) { res.status(400).json({ error: 'Faltan el nombre, la categoría o la descripción del problema.' }); return; }
      const empDocT = await fetch(`${base0}/empresas/${empresaOperador}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const seqT = parseInt(empDocT.fields?.ticketSeq?.integerValue || '0', 10) + 1;
      await fetch(`${base0}/empresas/${empresaOperador}?updateMask.fieldPaths=ticketSeq`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { ticketSeq: { integerValue: String(seqT) } } })
      });
      const folioT = 'TK-' + String(seqT).padStart(4, '0');
      const str = (v, n) => ({ stringValue: String(v || '').trim().slice(0, n) });
      const num = (v) => ({ integerValue: String(Math.max(0, parseInt(v, 10) || 0)) });
      const fieldsT = {
        folio: { stringValue: folioT }, estado: { stringValue: 'ingresado' },
        creadaEn: { timestampValue: new Date().toISOString() },
        tomadoPor: { stringValue: perfilOp.fields?.nombre?.stringValue || '' },
        medio: str(b.medio, 30),
        nombre: { stringValue: nombreT }, rut: str(b.rut, 15), telefono: str(b.telefono, 20), edad: num(b.edad),
        calle: str(b.calle, 160), sector: str(b.sector, 80), comuna: str(b.comuna, 60), referencia: str(b.referencia, 200),
        personas: num(b.personas), adultosMayores: num(b.adultosMayores), ninos: num(b.ninos), discapacidad: num(b.discapacidad),
        electrodependiente: { booleanValue: b.electrodependiente === true },
        categoria: { stringValue: categoriaT }, prioridad: str(b.prioridad || 'media', 10),
        descripcion: { stringValue: descripcionT },
        necesidades: { arrayValue: { values: (Array.isArray(b.necesidades) ? b.necesidades.slice(0, 12) : []).map((x) => ({ stringValue: String(x).slice(0, 40) })) } },
        gestiones: { arrayValue: { values: [] } }
      };
      if (b.lat != null && !isNaN(Number(b.lat))) { fieldsT.lat = { doubleValue: Number(b.lat) }; fieldsT.lng = { doubleValue: Number(b.lng) }; }
      await fetch(`${base0}/empresas/${empresaOperador}/tickets`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: fieldsT })
      });
      res.status(200).json({ ok: true, folio: folioT });
      return;
    }
    if (accion === 'ticket-listar') {
      { const prTk = perfilOp.fields?.permisosOp?.mapValue?.fields || {}; if (!esSA && prTk.tickets?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a los tickets.' }); return; } }
      const docsT = await fetch(`${base0}/empresas/${empresaOperador}/tickets?pageSize=200`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const gv = (x) => x?.stringValue ?? '';
      const gi = (x) => x ? parseInt(x.integerValue || '0', 10) : 0;
      const tickets = (docsT.documents || []).map((dd) => {
        const ff = dd.fields || {};
        return {
          id: dd.name.split('/').pop(), folio: gv(ff.folio), estado: gv(ff.estado) || 'ingresado',
          creadaEn: ff.creadaEn?.timestampValue || null, tomadoPor: gv(ff.tomadoPor), medio: gv(ff.medio),
          nombre: gv(ff.nombre), rut: gv(ff.rut), telefono: gv(ff.telefono), edad: gi(ff.edad),
          calle: gv(ff.calle), sector: gv(ff.sector), comuna: gv(ff.comuna), referencia: gv(ff.referencia),
          personas: gi(ff.personas), adultosMayores: gi(ff.adultosMayores), ninos: gi(ff.ninos), discapacidad: gi(ff.discapacidad),
          electrodependiente: ff.electrodependiente?.booleanValue === true,
          categoria: gv(ff.categoria), prioridad: gv(ff.prioridad) || 'media', descripcion: gv(ff.descripcion),
          lat: ff.lat ? parseFloat(ff.lat.doubleValue) : null, lng: ff.lng ? parseFloat(ff.lng.doubleValue) : null,
          asignadoUid: gv(ff.asignadoUid), asignadoNombre: gv(ff.asignadoNombre), asignadoRol: gv(ff.asignadoRol), area: gv(ff.area),
          coasignados: (ff.coasignados?.arrayValue?.values || []).map((cv) => { const cf = cv.mapValue?.fields || {}; return { uid: gv(cf.uid), nombre: gv(cf.nombre), rol: gv(cf.rol) }; }),
          tareas: (ff.tareas?.arrayValue?.values || []).map((tv) => { const tf = tv.mapValue?.fields || {}; return { id: gv(tf.id), texto: gv(tf.texto), asignadoUid: gv(tf.asignadoUid), asignadoNombre: gv(tf.asignadoNombre), estado: gv(tf.estado) || 'pendiente', creadaPor: gv(tf.creadaPor), creadaEn: tf.creadaEn?.timestampValue || null }; }),
          necesidades: (ff.necesidades?.arrayValue?.values || []).map((x) => x.stringValue),
          gestiones: (ff.gestiones?.arrayValue?.values || []).map((g) => { const gf = g.mapValue?.fields || {}; return { estado: gv(gf.estado), texto: gv(gf.texto), por: gv(gf.por), creadaEn: gf.creadaEn?.timestampValue || null }; })
        };
      }).sort((a, b2) => new Date(b2.creadaEn || 0) - new Date(a.creadaEn || 0)).slice(0, 80);
      res.status(200).json({ ok: true, tickets });
      return;
    }
    if (accion === 'ticket-tarea-crear' || accion === 'ticket-tarea-estado') {
      { const prTk = perfilOp.fields?.permisosOp?.mapValue?.fields || {}; if (!esSA && prTk.tickets?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a los tickets.' }); return; } }
      // El especialista asignado (o jefe/gerente) reparte el ticket en tareas concretas.
      const tidT = (req.body.ticketId || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(tidT)) { res.status(400).json({ error: 'Ticket no válido' }); return; }
      const rutaTT = `${base0}/empresas/${empresaOperador}/tickets/${tidT}`;
      const docTT = await fetch(rutaTT, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!docTT.fields) { res.status(404).json({ error: 'Ticket no encontrado' }); return; }
      const miRolT = perfilOp.fields?.rolEmpresa?.stringValue || '';
      const asignadoDelTicket = docTT.fields?.asignadoUid?.stringValue || '';
      const coasignadosT = (docTT.fields?.coasignados?.arrayValue?.values || []).map((cv) => cv.mapValue?.fields?.uid?.stringValue || '');
      const puedeGestionar = esSA || miRolT === 'jefe' || miRolT === 'gerente' || uid === asignadoDelTicket || coasignadosT.includes(uid);
      const tareasPrev = docTT.fields?.tareas?.arrayValue?.values || [];

      if (accion === 'ticket-tarea-crear') {
        if (!puedeGestionar) { res.status(403).json({ error: 'Solo el especialista asignado o el jefe puede repartir tareas.' }); return; }
        const textoT = String(req.body.texto || '').trim().slice(0, 400);
        if (!textoT) { res.status(400).json({ error: 'Escribe qué hay que hacer.' }); return; }
        if (tareasPrev.length >= 40) { res.status(400).json({ error: 'Llegaste al máximo de tareas.' }); return; }
        let nomEnc = '', uidEnc = (req.body.asignadoUid || '').trim();
        if (uidEnc) {
          if (!/^[A-Za-z0-9]+$/.test(uidEnc)) { res.status(400).json({ error: 'Encargado no válido' }); return; }
          const docE = await fetch(`${base0}/usuarios/${uidEnc}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
          nomEnc = docE.fields?.nombre?.stringValue || 'Encargado';
        }
        tareasPrev.push({ mapValue: { fields: {
          id: { stringValue: 't' + Date.now().toString(36) },
          texto: { stringValue: textoT },
          asignadoUid: { stringValue: uidEnc }, asignadoNombre: { stringValue: nomEnc },
          estado: { stringValue: 'pendiente' },
          creadaPor: { stringValue: perfilOp.fields?.nombre?.stringValue || '' },
          creadaEn: { timestampValue: new Date().toISOString() }
        } } });
        await fetch(`${rutaTT}?updateMask.fieldPaths=tareas`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { tareas: { arrayValue: { values: tareasPrev.slice(0, 40) } } } })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'ticket-tarea-estado') {
        const tareaId = String(req.body.tareaId || '');
        const estadoT = String(req.body.estado || '');
        if (!['pendiente', 'en_progreso', 'lista'].includes(estadoT)) { res.status(400).json({ error: 'Estado no válido' }); return; }
        let ok = false;
        const nuevas = tareasPrev.map((tv) => {
          const tf = tv.mapValue?.fields || {};
          if ((tf.id?.stringValue || '') !== tareaId) return tv;
          // Puede cambiarla quien gestiona el ticket o el propio encargado de la tarea.
          if (!(puedeGestionar || uid === (tf.asignadoUid?.stringValue || ''))) return tv;
          ok = true;
          return { mapValue: { fields: { ...tf, estado: { stringValue: estadoT } } } };
        });
        if (!ok) { res.status(403).json({ error: 'No puedes cambiar esa tarea.' }); return; }
        await fetch(`${rutaTT}?updateMask.fieldPaths=tareas`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { tareas: { arrayValue: { values: nuevas } } } })
        });
        res.status(200).json({ ok: true });
        return;
      }
    }
    if (accion === 'ticket-recomendados') {
      { const prTk = perfilOp.fields?.permisosOp?.mapValue?.fields || {}; if (!esSA && prTk.tickets?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a los tickets.' }); return; } }
      // Sugiere al personal ideal para un ticket: especialidad/cargo que calza,
      // en turno hoy, y con menos carga (menos tickets abiertos).
      const tidR = (req.body.ticketId || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(tidR)) { res.status(400).json({ error: 'Ticket no válido' }); return; }
      const docTR = await fetch(`${base0}/empresas/${empresaOperador}/tickets/${tidR}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!docTR.fields) { res.status(404).json({ error: 'Ticket no encontrado' }); return; }
      const categoria = docTR.fields?.categoria?.stringValue || 'otro';
      const KEYS = {
        anegamiento: { kw: ['bomba','agua','gasfiter','gásfiter','plomero','rescat','emergencia','maquinaria','operador','motobomba','protección civil'], area: '🚨 Emergencias' },
        vivienda: { kw: ['carpint','albañil','maestro','obras','techumbre','construc','ingenier','pintor'], area: '🏗 Obras / reparaciones' },
        luz: { kw: ['electric','eléctric','alumbrado','telecom'], area: '⚡ Eléctrica' },
        agua: { kw: ['gasfiter','gásfiter','plomero','agua','sanitar'], area: '💧 Agua' },
        arbol: { kw: ['podad','jardin','motosierra','áreas verdes','areas verdes','maquinaria','operador'], area: '🏗 Obras / reparaciones' },
        albergue: { kw: ['social','dideco','albergue','asisten','logística','logistica','bodega','coordinador'], area: '🛏 Social / albergue' },
        salud: { kw: ['paramédic','paramedic','enfermer','médic','medic','salud','samu'], area: '💊 Salud' },
        rescate: { kw: ['rescat','bombero','buzo','emergencia','protección civil','proteccion civil'], area: '🚨 Emergencias' },
        seguridad: { kw: ['guardia','seguridad','vigilante','sereno','inspector','fiscaliz'], area: '🛡 Seguridad' },
        animal: { kw: ['veterinar','animal'], area: '📌 Otra' },
        otro: { kw: [], area: '📌 Otra' }
      };
      const cfg = KEYS[categoria] || KEYS.otro;
      // Personal de la empresa.
      const clientesR = await listarClientes(accessToken);
      const personalR = clientesR.filter((c) => c.empresaId === empresaOperador && c.rolEmpresa && c.rolEmpresa !== 'jefe' && c.rolEmpresa !== 'gerente');
      // Tickets abiertos por persona (carga actual).
      const ticketsR = await fetch(`${base0}/empresas/${empresaOperador}/tickets?pageSize=200`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const cargaPor = {};
      (ticketsR.documents || []).forEach((dd) => {
        const est = dd.fields?.estado?.stringValue || '';
        const au = dd.fields?.asignadoUid?.stringValue || '';
        if (au && est !== 'cerrado' && est !== 'resuelto') cargaPor[au] = (cargaPor[au] || 0) + 1;
      });
      // En turno hoy (marcó asistencia).
      const hoyR = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Santiago', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
      const asisR = await fetch(`${base0}/empresas/${empresaOperador}/asistencia?pageSize=300`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const enTurno = {};
      (asisR.documents || []).forEach((dd) => { if (dd.fields?.fecha?.stringValue === hoyR && dd.fields?.entradaHora?.stringValue) enTurno[dd.fields?.uid?.stringValue || ''] = true; });
      // Puntaje.
      const match = (txt) => cfg.kw.some((k) => (txt || '').toLowerCase().includes(k));
      const rank = personalR.map((p) => {
        let score = 0; const motivos = [];
        if (match(p.especialidad)) { score += 50; motivos.push('🏷 ' + p.especialidad); }
        if (match(p.cargoMunicipal)) { score += 35; if (!match(p.especialidad)) motivos.push('🏛 ' + p.cargoMunicipal); }
        if (p.rolEmpresa === 'movil' || p.rolEmpresa === 'tecnico') score += 12;
        if (enTurno[p.uid]) { score += 25; motivos.push('🟢 en turno'); } else { motivos.push('⚪ sin marcar turno'); }
        const carga = cargaPor[p.uid] || 0;
        score -= carga * 8;
        motivos.push(carga + ' ticket' + (carga === 1 ? '' : 's') + ' abierto' + (carga === 1 ? '' : 's'));
        return { uid: p.uid, nombre: p.nombre || 'Sin nombre', especialidad: p.especialidad || '', cargo: p.cargoMunicipal || '', rol: p.rolEmpresa, enTurno: !!enTurno[p.uid], carga, score, motivo: motivos.join(' · ') };
      }).sort((a, b) => b.score - a.score).slice(0, 6);
      res.status(200).json({ ok: true, categoria, areaSugerida: cfg.area, recomendados: rank });
      return;
    }
    if (accion === 'ticket-coasignar') {
      // Suma (o quita) personas adicionales al ticket, además del líder asignado.
      { const prTk = perfilOp.fields?.permisosOp?.mapValue?.fields || {}; if (!esSA && prTk.tickets?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a los tickets.' }); return; } }
      const tidC = (req.body.ticketId || '').trim();
      const uidC = (req.body.personaUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(tidC) || !/^[A-Za-z0-9]+$/.test(uidC)) { res.status(400).json({ error: 'Datos no válidos' }); return; }
      const rutaTC = `${base0}/empresas/${empresaOperador}/tickets/${tidC}`;
      const docTC = await fetch(rutaTC, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!docTC.fields) { res.status(404).json({ error: 'Ticket no encontrado' }); return; }
      const miRolC = perfilOp.fields?.rolEmpresa?.stringValue || '';
      const leadC = docTC.fields?.asignadoUid?.stringValue || '';
      if (!(esSA || miRolC === 'jefe' || miRolC === 'gerente' || uid === leadC)) { res.status(403).json({ error: 'Solo el líder asignado o el jefe puede sumar gente.' }); return; }
      let lista = (docTC.fields?.coasignados?.arrayValue?.values || []);
      const yaEsta = lista.some((cv) => (cv.mapValue?.fields?.uid?.stringValue || '') === uidC);
      const esLider = uidC === leadC;
      if (req.body.quitar) {
        lista = lista.filter((cv) => (cv.mapValue?.fields?.uid?.stringValue || '') !== uidC);
      } else if (!yaEsta && !esLider) {
        if (lista.length >= 15) { res.status(400).json({ error: 'Máximo de personas en el ticket.' }); return; }
        const docP = await fetch(`${base0}/usuarios/${uidC}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        if (!esSA && (docP.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
        lista.push({ mapValue: { fields: { uid: { stringValue: uidC }, nombre: { stringValue: docP.fields?.nombre?.stringValue || 'Persona' }, rol: { stringValue: docP.fields?.rolEmpresa?.stringValue || '' } } } });
      }
      const gestC = docTC.fields?.gestiones?.arrayValue?.values || [];
      gestC.push({ mapValue: { fields: { estado: { stringValue: docTC.fields?.estado?.stringValue || 'asignado' }, texto: { stringValue: (req.body.quitar ? 'Quitó a una persona del ticket' : 'Sumó una persona al ticket') }, por: { stringValue: perfilOp.fields?.nombre?.stringValue || '' }, creadaEn: { timestampValue: new Date().toISOString() } } } });
      await fetch(`${rutaTC}?updateMask.fieldPaths=coasignados&updateMask.fieldPaths=gestiones`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { coasignados: { arrayValue: { values: lista } }, gestiones: { arrayValue: { values: gestC.slice(-30) } } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'ticket-asignar') {
      { const prTk = perfilOp.fields?.permisosOp?.mapValue?.fields || {}; if (!esSA && prTk.tickets?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a los tickets.' }); return; } }
      // Asignar el ticket clasificado al especialista del área.
      const tidA = (req.body.ticketId || '').trim();
      const espUid = (req.body.asignadoUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(tidA) || !/^[A-Za-z0-9]+$/.test(espUid)) { res.status(400).json({ error: 'Ticket o especialista no válido' }); return; }
      const areaA = String(req.body.area || '').trim().slice(0, 40);
      const docEsp = await fetch(`${base0}/usuarios/${espUid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!esSA && (docEsp.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
      const nomEsp = docEsp.fields?.nombre?.stringValue || 'Especialista';
      const rolEsp = docEsp.fields?.rolEmpresa?.stringValue || '';
      const rutaTA = `${base0}/empresas/${empresaOperador}/tickets/${tidA}`;
      const docTA = await fetch(rutaTA, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!docTA.fields) { res.status(404).json({ error: 'Ticket no encontrado' }); return; }
      const gestA = docTA.fields?.gestiones?.arrayValue?.values || [];
      gestA.push({ mapValue: { fields: {
        estado: { stringValue: 'asignado' },
        texto: { stringValue: ('Asignado a ' + nomEsp + (areaA ? ' — área ' + areaA : '')).slice(0, 300) },
        por: { stringValue: perfilOp.fields?.nombre?.stringValue || '' },
        creadaEn: { timestampValue: new Date().toISOString() }
      } } });
      await fetch(`${rutaTA}?updateMask.fieldPaths=estado&updateMask.fieldPaths=gestiones&updateMask.fieldPaths=asignadoUid&updateMask.fieldPaths=asignadoNombre&updateMask.fieldPaths=asignadoRol&updateMask.fieldPaths=area`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { estado: { stringValue: 'asignado' }, gestiones: { arrayValue: { values: gestA.slice(-30) } }, asignadoUid: { stringValue: espUid }, asignadoNombre: { stringValue: nomEsp }, asignadoRol: { stringValue: rolEsp }, area: { stringValue: areaA } } })
      });
      res.status(200).json({ ok: true, asignadoNombre: nomEsp });
      return;
    }
    if (accion === 'ticket-estado') {
      { const prTk = perfilOp.fields?.permisosOp?.mapValue?.fields || {}; if (!esSA && prTk.tickets?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a los tickets.' }); return; } }
      const tid = (req.body.ticketId || '').trim();
      const estadoT = String(req.body.estado || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(tid) || !['ingresado', 'asignado', 'en_gestion', 'derivado', 'resuelto', 'cerrado'].includes(estadoT)) { res.status(400).json({ error: 'Ticket o estado no válido' }); return; }
      const rutaT = `${base0}/empresas/${empresaOperador}/tickets/${tid}`;
      const docT = await fetch(rutaT, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      if (!docT.fields) { res.status(404).json({ error: 'Ticket no encontrado' }); return; }
      const gestPrev = docT.fields?.gestiones?.arrayValue?.values || [];
      gestPrev.push({ mapValue: { fields: {
        estado: { stringValue: estadoT },
        texto: { stringValue: String(req.body.nota || '').trim().slice(0, 500) },
        por: { stringValue: perfilOp.fields?.nombre?.stringValue || '' },
        creadaEn: { timestampValue: new Date().toISOString() }
      } } });
      await fetch(`${rutaT}?updateMask.fieldPaths=estado&updateMask.fieldPaths=gestiones`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { estado: { stringValue: estadoT }, gestiones: { arrayValue: { values: gestPrev.slice(-30) } } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'despachar-movil') {
      const prawDM = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawDM.moviles?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la gestión de móviles.' }); return; }
      // El operador que atiende otorga el SOS a un móvil.
      const cUid = (req.body.clienteUid || '').trim();
      const aId = (req.body.alertaId || '').trim();
      const mUid = (req.body.movilUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(cUid) || !/^[A-Za-z0-9]+$/.test(aId) || !/^[A-Za-z0-9]+$/.test(mUid)) { res.status(400).json({ error: 'Datos no válidos' }); return; }
      const [docCli, docMov] = await Promise.all([
        fetch(`${base0}/usuarios/${cUid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {}),
        fetch(`${base0}/usuarios/${mUid}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {})
      ]);
      const empC = docCli.fields?.empresaId?.stringValue || 'sos360-la-serena';
      const empM = docMov.fields?.empresaId?.stringValue || 'sos360-la-serena';
      if (!esSA && (empC !== empresaOperador || empM !== empresaOperador)) { res.status(403).json({ error: 'Cliente o móvil de otra empresa.' }); return; }
      if (docMov.fields?.rolEmpresa?.stringValue !== 'movil') { res.status(400).json({ error: 'Esa persona no es un móvil de reacción.' }); return; }
      await fetch(`${base0}/usuarios/${cUid}/alertas/${aId}?updateMask.fieldPaths=movilAsignado&updateMask.fieldPaths=movilNombre&updateMask.fieldPaths=movilEstado&updateMask.fieldPaths=movilDespachadoEn`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: {
          movilAsignado: { stringValue: mUid },
          movilNombre: { stringValue: docMov.fields?.nombre?.stringValue || 'Móvil' },
          movilEstado: { stringValue: 'despachado' },
          movilDespachadoEn: { timestampValue: new Date().toISOString() }
        } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'recorrido-set') {
      // Solo el gerente de seguridad (o el jefe) puede mandar recorridos a los móviles.
      const miRolRec = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolRec !== 'jefe' && miRolRec !== 'gerente') { res.status(403).json({ error: 'Solo el gerente o el jefe puede mandar recorridos a los móviles.' }); return; }
      const prawG_moviles = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawG_moviles.moviles?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la gestión de móviles.' }); return; }
      const mUid = (req.body.movilUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(mUid)) { res.status(400).json({ error: 'Móvil no válido' }); return; }
      const entradas = Array.isArray(req.body.paradas) ? req.body.paradas : [];
      const clientes = await listarClientes(accessToken);
      const porUid = {};
      clientes.forEach((c) => { porUid[c.uid] = c; });
      const values = entradas.map((p) => {
        // Acepta un uid de cliente (string) o un objeto {clienteUid, nombre, direccion, lat, lng}.
        const obj = (typeof p === 'string') ? { clienteUid: p } : (p || {});
        const cUid = /^[A-Za-z0-9]+$/.test(obj.clienteUid || '') ? obj.clienteUid : '';
        const c = cUid ? (porUid[cUid] || {}) : {};
        const nombre = obj.nombre || c.local || c.nombre || 'Punto de ronda';
        const direccion = obj.direccion || c.direccion || '';
        const lat = (obj.lat != null) ? Number(obj.lat) : null;
        const lng = (obj.lng != null) ? Number(obj.lng) : null;
        const f = {
          clienteUid: { stringValue: cUid },
          nombre: { stringValue: String(nombre).slice(0, 120) },
          direccion: { stringValue: String(direccion).slice(0, 200) },
          estado: { stringValue: 'pendiente' },
          nota: { stringValue: '' }, foto: { stringValue: '' }, visitadaEn: { stringValue: '' }
        };
        if (lat != null && !isNaN(lat)) f.lat = { doubleValue: lat };
        if (lng != null && !isNaN(lng)) f.lng = { doubleValue: lng };
        return { mapValue: { fields: f } };
      });
      await fetch(`${base0}/empresas/${empresaOperador}/recorridos/${mUid}?updateMask.fieldPaths=fecha&updateMask.fieldPaths=paradas`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { fecha: { stringValue: new Date().toISOString().slice(0, 10) }, paradas: { arrayValue: { values } } } })
      });
      res.status(200).json({ ok: true, total: values.length });
      return;
    }
    if (accion === 'recorrido-cancelar') {
      // El gerente o el jefe cancela el recorrido asignado a un móvil.
      const miRolRC = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolRC !== 'jefe' && miRolRC !== 'gerente') { res.status(403).json({ error: 'Solo el gerente o el jefe puede cancelar recorridos.' }); return; }
      const prawRC = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
      if (!esSA && prawRC.moviles?.booleanValue === false) { res.status(403).json({ error: 'La plataforma cortó tu acceso a la gestión de móviles.' }); return; }
      const mUidC = (req.body.movilUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(mUidC)) { res.status(400).json({ error: 'Móvil no válido' }); return; }
      await fetch(`${base0}/empresas/${empresaOperador}/recorridos/${mUidC}`, {
        method: 'DELETE', headers: { Authorization: `Bearer ${accessToken}` }
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'emp-codigo') {
      // Código de equipo de la empresa del operador (para sumar personal).
      const rutaEmp = `${base0}/empresas/${empresaOperador}`;
      let doc = await fetch(rutaEmp, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      let cod = doc.fields?.codigoEquipo?.stringValue;
      if (!cod || req.body.regenerar) {
        cod = Math.random().toString(36).slice(2, 8).toUpperCase();
        await fetch(`${rutaEmp}?updateMask.fieldPaths=codigoEquipo`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { codigoEquipo: { stringValue: cod } } })
        });
      }
      res.status(200).json({ ok: true, codigo: cod });
      return;
    }
    if (accion === 'emp-operador') {
      // El jefe/gerente promueve (o quita) a un integrante como operador de la central.
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe' && miRol !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente puede nombrar operadores.' }); return; }
      const destino = (req.body.personalUid || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(destino)) { res.status(400).json({ error: 'Persona no válida' }); return; }
      const docD = await fetch(`${base0}/usuarios/${destino}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const empD = docD.fields?.empresaId?.stringValue || 'sos360-la-serena';
      if (!esSA && empD !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
      // operadorDe = empresa (lo habilita como operador) o vacío (lo quita).
      await fetch(`${base0}/usuarios/${destino}?updateMask.fieldPaths=operadorDe`, {
        method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { operadorDe: { stringValue: req.body.quitar ? '' : empD } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'emp-personal') {
      // Personal de la empresa: incluye si es operador o no.
      // Personal de la empresa del operador: integrantes con rolEmpresa.
      const clientesTodos = await listarClientes(accessToken);
      const personal = clientesTodos.filter((c) => c.empresaId === empresaOperador && c.rolEmpresa)
        .map((c) => ({ uid: c.uid, nombre: c.nombre || c.local || 'Sin nombre', telefono: c.telefono || '', rol: c.rolEmpresa, esOperador: !!c.operadorDe, especialidad: c.especialidad || '', grupoId: c.grupoId || '', cargoMunicipal: c.cargoMunicipal || '' }));
      // Correos de esas cuentas.
      try {
        const lk = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/accounts:lookup`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ localId: personal.map((p) => p.uid) })
        }).then((r) => r.json());
        (lk.users || []).forEach((u) => { const p = personal.find((x) => x.uid === u.localId); if (p) p.email = u.email || ''; });
      } catch (e) {}
      // Especialidades y grupos que definió el jefe de la empresa.
      let especialidades = [], grupos = [], cargosMun = [];
      try {
        const empDocP = await fetch(`${base0}/empresas/${empresaOperador}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        especialidades = (empDocP.fields?.especialidades?.arrayValue?.values || []).map((x) => x.stringValue);
        cargosMun = (empDocP.fields?.cargosMun?.arrayValue?.values || []).map((x) => x.stringValue);
        grupos = (empDocP.fields?.grupos?.arrayValue?.values || []).map((g) => { const gf = g.mapValue?.fields || {}; return { id: gf.id?.stringValue || '', nombre: gf.nombre?.stringValue || '', color: gf.color?.stringValue || '#9d8fff', lider: gf.lider?.stringValue || '' }; });
      } catch (e) {}
      let rolesCustom = [];
      try {
        const empRC = await fetch(`${base0}/empresas/${empresaOperador}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        rolesCustom = (empRC.fields?.rolesCustom?.arrayValue?.values || []).map((rv) => { const rf = rv.mapValue?.fields || {}; return { id: rf.id?.stringValue || '', nombre: rf.nombre?.stringValue || '' }; });
      } catch (e) {}
      res.status(200).json({ ok: true, personal, empresa: empresaOperador, especialidades, grupos, cargosMun, rolesCustom });
      return;
    }
    if (accion === 'emp-especialidades-set' || accion === 'emp-cargos-set' || accion === 'emp-grupo-crear' || accion === 'emp-grupo-eliminar' || accion === 'emp-persona-set') {
      // Configuración de especialidades y grupos: solo jefe/gerente.
      const miRolE = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRolE !== 'jefe' && miRolE !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente gestiona el equipo.' }); return; }
      const rutaEmpE = `${base0}/empresas/${empresaOperador}`;
      const empDocE = await fetch(rutaEmpE, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});

      if (accion === 'emp-cargos-set') {
        const listaC = (Array.isArray(req.body.cargos) ? req.body.cargos : []).map((x) => String(x).trim().slice(0, 60)).filter(Boolean).slice(0, 60);
        await fetch(`${rutaEmpE}?updateMask.fieldPaths=cargosMun`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { cargosMun: { arrayValue: { values: listaC.map((x) => ({ stringValue: x })) } } } })
        });
        res.status(200).json({ ok: true, cargos: listaC });
        return;
      }
      if (accion === 'emp-especialidades-set') {
        const lista = (Array.isArray(req.body.especialidades) ? req.body.especialidades : []).map((x) => String(x).trim().slice(0, 40)).filter(Boolean).slice(0, 40);
        await fetch(`${rutaEmpE}?updateMask.fieldPaths=especialidades`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { especialidades: { arrayValue: { values: lista.map((x) => ({ stringValue: x })) } } } })
        });
        res.status(200).json({ ok: true, especialidades: lista });
        return;
      }
      if (accion === 'emp-grupo-crear') {
        const nombreG = String(req.body.nombre || '').trim().slice(0, 50);
        if (!nombreG) { res.status(400).json({ error: 'Ponle un nombre al grupo.' }); return; }
        const gruposPrev = empDocE.fields?.grupos?.arrayValue?.values || [];
        if (gruposPrev.length >= 30) { res.status(400).json({ error: 'Llegaste al máximo de grupos.' }); return; }
        const gid = 'g' + Date.now().toString(36);
        gruposPrev.push({ mapValue: { fields: { id: { stringValue: gid }, nombre: { stringValue: nombreG }, color: { stringValue: String(req.body.color || '#9d8fff').slice(0, 9) }, lider: { stringValue: String(req.body.lider || '').slice(0, 40) } } } });
        await fetch(`${rutaEmpE}?updateMask.fieldPaths=grupos`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { grupos: { arrayValue: { values: gruposPrev } } } })
        });
        res.status(200).json({ ok: true, id: gid });
        return;
      }
      if (accion === 'emp-grupo-eliminar') {
        const gid = String(req.body.grupoId || '');
        const gruposPrev = (empDocE.fields?.grupos?.arrayValue?.values || []).filter((g) => (g.mapValue?.fields?.id?.stringValue || '') !== gid);
        await fetch(`${rutaEmpE}?updateMask.fieldPaths=grupos`, {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: { grupos: { arrayValue: { values: gruposPrev } } } })
        });
        res.status(200).json({ ok: true });
        return;
      }
      if (accion === 'emp-persona-set') {
        // Asignar especialidad y/o grupo a una persona.
        const destinoP = (req.body.personalUid || '').trim();
        if (!/^[A-Za-z0-9]+$/.test(destinoP)) { res.status(400).json({ error: 'Persona no válida' }); return; }
        const docDP = await fetch(`${base0}/usuarios/${destinoP}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        if (!esSA && (docDP.fields?.empresaId?.stringValue || 'sos360-la-serena') !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
        const campos = {}, masks = [];
        if (req.body.especialidad != null) { campos.especialidad = { stringValue: String(req.body.especialidad).slice(0, 40) }; masks.push('especialidad'); }
        if (req.body.grupoId != null) { campos.grupoId = { stringValue: String(req.body.grupoId).slice(0, 30) }; masks.push('grupoId'); }
        if (req.body.cargoMunicipal != null) { campos.cargoMunicipal = { stringValue: String(req.body.cargoMunicipal).slice(0, 60) }; masks.push('cargoMunicipal'); }
        if (!masks.length) { res.status(400).json({ error: 'Nada que actualizar' }); return; }
        await fetch(`${base0}/usuarios/${destinoP}?` + masks.map((m) => `updateMask.fieldPaths=${m}`).join('&'), {
          method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: campos })
        });
        res.status(200).json({ ok: true });
        return;
      }
    }
    if (accion === 'emp-rol') {
      // Cambiar el rol de un integrante (solo jefe/gerente de la empresa).
      const miRol = perfilOp.fields?.rolEmpresa?.stringValue || '';
      if (!esSA && miRol !== 'jefe' && miRol !== 'gerente') { res.status(403).json({ error: 'Solo el jefe o gerente puede cambiar roles.' }); return; }
      const destino = (req.body.personalUid || '').trim();
      const rol = (req.body.rol || '').trim();
      if (!/^[A-Za-z0-9]+$/.test(destino) || !(['jefe', 'gerente', 'empleado', 'tecnico', 'supervisor', 'guardia', 'movil'].includes(rol) || /^rc_[a-z0-9]+$/.test(rol))) { res.status(400).json({ error: 'Datos no válidos' }); return; }
      // Verificar que el destino sea de la misma empresa.
      const docD = await fetch(`${base0}/usuarios/${destino}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
      const empD = docD.fields?.empresaId?.stringValue || 'sos360-la-serena';
      if (!esSA && empD !== empresaOperador) { res.status(403).json({ error: 'Esa persona es de otra empresa.' }); return; }
      await fetch(`${base0}/usuarios/${destino}?updateMask.fieldPaths=rolEmpresa`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: { rolEmpresa: { stringValue: rol } } })
      });
      res.status(200).json({ ok: true });
      return;
    }
    if (accion === 'reportes') {
      // Reportes de incidentes de los clientes de la empresa del operador.
      const [lista, clientesTodos] = await Promise.all([
        fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery`, {
          method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ structuredQuery: { from: [{ collectionId: 'reportes', allDescendants: true }], limit: 80 } })
        }).then((r) => r.json()),
        listarClientes(accessToken)
      ]);
      const mios = new Set(clientesTodos.filter((c) => c.empresaId === empresaOperador).map((c) => c.uid));
      const nombreDe = {};
      clientesTodos.forEach((c) => { nombreDe[c.uid] = c.local || c.nombre || 'Cliente'; });
      const reportes = (lista || []).filter((r) => r.document).map((r) => {
        const parts = r.document.name.split('/');
        const repId = parts.pop(); parts.pop();
        const cuid = parts.pop();
        const f = r.document.fields || {};
        return {
          id: repId, clienteUid: cuid,
          cliente: f.anonimo?.booleanValue === true ? 'Anónimo' : (nombreDe[cuid] || 'Cliente'),
          categoria: f.categoria?.stringValue || 'Otro',
          icono: f.icono?.stringValue || '📌',
          texto: f.texto?.stringValue || '',
          foto: f.foto?.stringValue || null,
          anonimo: f.anonimo?.booleanValue === true,
          estado: f.estado?.stringValue || 'pendiente',
          creadaEn: f.creadaEn?.timestampValue || null
        };
      }).filter((x) => mios.has(x.clienteUid))
        .sort((a, b) => new Date(b.creadaEn || 0) - new Date(a.creadaEn || 0)).slice(0, 25);
      res.status(200).json({ ok: true, reportes });
      return;
    }

    if (accion === 'codigo') {
      const resultado = await obtenerOGenerarCodigoOperador(accessToken, uid);
      res.status(200).json({ ok: true, codigo: resultado.codigo, creado: resultado.creado });
      return;
    }

    const [clientesTodos, alertasTodas] = await Promise.all([
      listarClientes(accessToken),
      listarAlertasRecientes(accessToken)
    ]);
    // Aislamiento: solo clientes de la empresa del operador, y solo SUS alertas.
    const clientes = clientesTodos.filter((c) => c.empresaId === empresaOperador);
    const uidsEmpresa = new Set(clientes.map((c) => c.uid));
    const alertasRecientes = alertasTodas.filter((a) => uidsEmpresa.has(a.clienteUid));
    const alertas = derivarAlertasActivas(alertasRecientes);

    const stats = calcularStats(alertasRecientes);
    stats.totalActivas = alertas.length;
    stats.totalClientes = clientes.length;

    const historial = alertasRecientes.slice(0, 120);

    // Funciones del operador: las de SU empresa (o las de plataforma si es la nuestra).
    const rutaFn = empresaOperador === 'sos360-la-serena'
      ? `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/plataforma/funciones`
      : `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/empresas/${empresaOperador}`;
    const docFn = await fetch(rutaFn, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
    const fraw = (docFn.fields?.flags || docFn.fields?.funciones)?.mapValue?.fields || {};
    const funciones = {};
    Object.keys(fraw).forEach((k) => { funciones[k] = fraw[k].booleanValue !== false; });

    // Permisos del operador: (1) plantilla por rol que define el jefe (pirámide) y
    // (2) cortes individuales de la plataforma. Se aplica el más restrictivo.
    const praw = perfilOp.fields?.permisosOp?.mapValue?.fields || {};
    const permisos = { atender: true, clientes: true, historial: true, tecnico: true, exportar: true, zonas: true, credenciales: true, moviles: true, asistencia: true, operativos: true, encurso: true, registro: true, llamados: true, tickets: true };
    const miRolE = perfilOp.fields?.rolEmpresa?.stringValue || '';
    let rolCustomNombre = '';
    if (!esSA && miRolE && miRolE !== 'jefe') {
      try {
        const empDocP = await fetch(`${base0}/empresas/${empresaOperador}`, { headers: { Authorization: `Bearer ${accessToken}` } }).then((r) => r.ok ? r.json() : {});
        if (/^rc_/.test(miRolE)) {
          // Rol personalizado: sus permisos son la base.
          const rc = (empDocP.fields?.rolesCustom?.arrayValue?.values || []).map((rv) => rv.mapValue?.fields || {}).find((rf) => (rf.id?.stringValue || '') === miRolE);
          if (rc) { rolCustomNombre = rc.nombre?.stringValue || ''; const pf = rc.permisos?.mapValue?.fields || {}; Object.keys(permisos).forEach((k) => { if (pf[k]?.booleanValue === false) permisos[k] = false; }); }
        } else {
          const rp = empDocP.fields?.rolesPermisos?.mapValue?.fields?.[miRolE]?.mapValue?.fields;
          if (rp) { Object.keys(permisos).forEach((k) => { if (rp[k]?.booleanValue === false) permisos[k] = false; }); }
        }
      } catch (e) {}
    }
    Object.keys(praw).forEach((k) => { if (praw[k].booleanValue === false) permisos[k] = false; });

    res.status(200).json({ ok: true, clientes, alertas, historial, stats, esSuperadmin: esSA, esMaestra: uid === CUENTA_MAESTRA, miUid: uid, rolEmpresa: perfilOp.fields?.rolEmpresa?.stringValue || '', esRolCustom: /^rc_/.test(miRolE), rolCustomNombre, empresaId: empresaOperador, permisos, funciones });
  } catch (err) {
    console.error('Error en panel operador:', err);
    res.status(500).json({ error: err.message || 'Error interno del servidor' });
  }
}
