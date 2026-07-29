// ── 🗓 INFORMES PROGRAMADOS (Módulo 6: "programación de informes periódicos") ──
// Lo llama el cron de Vercel cada mañana (07:00 hora de Chile). Para cada empresa
// con el informe automático encendido: cuenta la actividad de AYER (alarmas,
// reportes, operativos), guarda el informe en empresas/{id}/informes/{fecha} y
// avisa por push a los operadores. Los lunes genera además el semanal (7 días)
// y los días 1 el mensual (30 días): diarios, semanales y mensuales, como piden
// las bases. El informe completo se abre en la plataforma (vista Informes).
import crypto from 'crypto';

const PROJECT_ID = 'vivanet-f8ac2';
const BASE = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function obtenerAccessToken() {
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  if (!clientEmail || !privateKey) throw new Error('Faltan credenciales de Firebase en Vercel');
  const nowSec = Math.floor(Date.now() / 1000);
  const claim = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    iat: nowSec, exp: nowSec + 3600
  };
  const unsigned = `${base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64url(JSON.stringify(claim))}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned); signer.end();
  const signature = signer.sign(privateKey).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` })
  });
  const data = await resp.json();
  if (!data.access_token) throw new Error('No se pudo obtener el token de Google');
  return data.access_token;
}

const diaCL = (d) => new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Santiago', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);

export default async function handler(req, res) {
  // Solo el cron de Vercel (o alguien con el secreto) puede disparar la generación.
  const auth = req.headers.authorization || '';
  const esCron = String(req.headers['user-agent'] || '').includes('vercel-cron');
  const conSecreto = process.env.CRON_SECRET && auth === `Bearer ${process.env.CRON_SECRET}`;
  if (!esCron && !conSecreto) { res.status(401).json({ error: 'No autorizado' }); return; }

  try {
    const token = await obtenerAccessToken();
    const H = { Authorization: `Bearer ${token}` };
    const HJ = { ...H, 'Content-Type': 'application/json' };

    const ahora = new Date();
    const hoy = diaCL(ahora);
    const ayer = diaCL(new Date(ahora.getTime() - 24 * 3600 * 1000));
    // Lunes en Chile → semanal; día 1 del mes → mensual.
    const dowCL = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Santiago', weekday: 'short' }).format(ahora);
    const diaMesCL = parseInt(new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Santiago', day: '2-digit' }).format(ahora), 10);
    const tipos = [{ tipo: 'diario', dias: 1 }];
    if (dowCL === 'Mon') tipos.push({ tipo: 'semanal', dias: 7 });
    if (diaMesCL === 1) tipos.push({ tipo: 'mensual', dias: 30 });

    // Datos base: empresas, usuarios (clientes + operadores + tokens), alertas.
    const [respEmp, respU, respA] = await Promise.all([
      fetch(`${BASE}/empresas?pageSize=100`, { headers: H }).then((r) => r.ok ? r.json() : {}),
      fetch(`${BASE}/usuarios?pageSize=300`, { headers: H }).then((r) => r.ok ? r.json() : {}),
      fetch(`${BASE}:runQuery`, { method: 'POST', headers: HJ, body: JSON.stringify({ structuredQuery: { from: [{ collectionId: 'alertas', allDescendants: true }], limit: 300 } }) }).then((r) => r.json())
    ]);
    const usuarios = (respU.documents || []).map((d) => ({
      uid: d.name.split('/').pop(), f: d.fields || {},
      empresaId: d.fields?.empresaId?.stringValue || d.fields?.operadorDe?.stringValue || 'sos360-la-serena'
    }));
    const alertas = (respA || []).filter((r) => r.document).map((r) => {
      const parts = r.document.name.split('/'); parts.pop(); parts.pop();
      return { clienteUid: parts.pop(), creadaEn: r.document.fields?.creadaEn?.timestampValue || null, atendidaEn: r.document.fields?.atendidaEn?.timestampValue || null };
    });

    const resultados = [];
    for (const de of (respEmp.documents || [])) {
      const empId = de.name.split('/').pop();
      if (de.fields?.informeAuto?.booleanValue === false) continue; // apagado por la empresa
      if (de.fields?.estado?.stringValue === 'suspendida') continue;
      const misUids = new Set(usuarios.filter((u) => u.empresaId === empId).map((u) => u.uid));

      for (const { tipo, dias } of tipos) {
        const corte = Date.now() - dias * 24 * 3600 * 1000;
        const delPeriodo = alertas.filter((a) => misUids.has(a.clienteUid) && a.creadaEn && new Date(a.creadaEn).getTime() >= corte);
        const resumen = {
          alertas: delPeriodo.length,
          atendidas: delPeriodo.filter((a) => a.atendidaEn).length
        };
        // Operativos del período (colección por empresa).
        try {
          const rm = await fetch(`${BASE}/empresas/${empId}/misiones?pageSize=100`, { headers: H }).then((r) => r.ok ? r.json() : {});
          resumen.operativos = (rm.documents || []).filter((d) => {
            const t = d.fields?.creadaEn?.timestampValue; return t && new Date(t).getTime() >= corte;
          }).length;
        } catch (e) { resumen.operativos = 0; }

        const docId = `${tipo}_${ayer}`;
        await fetch(`${BASE}/empresas/${empId}/informes/${docId}?updateMask.fieldPaths=tipo&updateMask.fieldPaths=fecha&updateMask.fieldPaths=dias&updateMask.fieldPaths=resumen&updateMask.fieldPaths=generadoEn`, {
          method: 'PATCH', headers: HJ,
          body: JSON.stringify({ fields: {
            tipo: { stringValue: tipo }, fecha: { stringValue: ayer }, dias: { integerValue: String(dias) },
            resumen: { mapValue: { fields: { alertas: { integerValue: String(resumen.alertas) }, atendidas: { integerValue: String(resumen.atendidas) }, operativos: { integerValue: String(resumen.operativos || 0) } } } },
            generadoEn: { timestampValue: new Date().toISOString() }
          } })
        });
        // Marca en la empresa cuándo se generó el último (la app lo muestra).
        await fetch(`${BASE}/empresas/${empId}?updateMask.fieldPaths=ultimoInformeEn&updateMask.fieldPaths=ultimoInformeTipo`, {
          method: 'PATCH', headers: HJ,
          body: JSON.stringify({ fields: { ultimoInformeEn: { timestampValue: new Date().toISOString() }, ultimoInformeTipo: { stringValue: tipo } } })
        });

        // Push a los operadores de la empresa que tengan token.
        const NOM = { diario: 'diario', semanal: 'semanal', mensual: 'mensual' };
        const cuerpoPush = `${resumen.alertas} alarma${resumen.alertas === 1 ? '' : 's'} · ${resumen.atendidas} atendida${resumen.atendidas === 1 ? '' : 's'} · ${resumen.operativos || 0} operativo${(resumen.operativos || 0) === 1 ? '' : 's'}. Ábrelo en 📊 Informes.`;
        const conToken = usuarios.filter((u) => u.empresaId === empId && u.f.fcmToken?.stringValue);
        for (const u of conToken.slice(0, 20)) {
          try {
            await fetch(`https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`, {
              method: 'POST', headers: HJ,
              body: JSON.stringify({ message: {
                token: u.f.fcmToken.stringValue,
                notification: { title: `📊 Informe ${NOM[tipo]} listo — SOS24`, body: cuerpoPush },
                webpush: { fcmOptions: { link: 'https://www.sos24.cl/' } }
              } })
            });
          } catch (e) {}
        }
        resultados.push({ empresa: empId, tipo, ...resumen, avisados: conToken.length });
      }
    }
    res.status(200).json({ ok: true, fecha: hoy, generados: resultados.length, detalle: resultados });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error generando informes' });
  }
}
