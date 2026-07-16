// Función serverless de Vercel: /api/soy-operador
// Dice si el usuario autenticado es un operador de la central. El servidor es
// la única fuente de verdad: la lista sale de OPERADORES_UIDS (variable de
// entorno en Vercel, uids separados por coma). Si no existe, solo la cuenta
// central original. El cliente usa esto solo para decidir qué pantalla mostrar;
// el acceso a los datos lo siguen validando los demás endpoints por su cuenta.

const FIREBASE_API_KEY = 'AIzaSyCRAFZXVB6VZ8vAVoMF3WDvjcmUCiInP2g'; // clave pública del cliente web
const CENTRAL_UID = 'ziDCZASJ7GaMoBhUDw7uPbKmFgE2'; // cuenta de Diego (central)
const OPERADORES = (process.env.OPERADORES_UIDS || CENTRAL_UID).split(',').map((s) => s.trim()).filter(Boolean);

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
  const { idToken } = req.body || {};
  if (!idToken) {
    res.status(400).json({ error: 'Falta idToken' });
    return;
  }
  try {
    const uid = await verificarUsuario(idToken);
    res.status(200).json({ ok: true, operador: !!uid && OPERADORES.includes(uid) });
  } catch (err) {
    console.error('Error en soy-operador:', err);
    res.status(200).json({ ok: false, operador: false });
  }
}
