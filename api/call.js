// Función serverless de Vercel: /api/call
// Inicia una llamada telefónica real vía Twilio cuando se activa una alerta SOS,
// para que suene como una alarma en el teléfono del contacto de emergencia.
// Las credenciales de Twilio quedan ocultas en el servidor (variables de entorno).

export default async function handler(req, res) {
    if (req.method !== 'POST') {
          res.status(405).json({ error: 'Método no permitido' });
          return;
    }

  const { telefono, mensaje } = req.body || {};

  if (!telefono || typeof telefono !== 'string') {
        res.status(400).json({ error: 'Falta el teléfono del contacto' });
        return;
  }

  const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_PHONE_NUMBER;

  if (!accountSid || !authToken || !fromNumber) {
        res.status(500).json({ error: 'Falta configurar Twilio en Vercel (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER)' });
        return;
  }

  const textoAlarma = (mensaje || 'Alerta de pánico activada. Por favor revisa la aplicación Vigil de inmediato.')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

  const twiml =
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<Response><Say language="es-MX" loop="5">${textoAlarma}</Say></Response>`;

  const auth = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
    const params = new URLSearchParams({
          To: telefono,
          From: fromNumber,
          Twiml: twiml
    });

  try {
        const response = await fetch(
                `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Calls.json`,
          {
                    method: 'POST',
                    headers: {
                                Authorization: `Basic ${auth}`,
                                'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: params
          }
              );

      const data = await response.json();

      if (!response.ok) {
              console.error('Error de Twilio:', response.status, data);
              res.status(502).json({ error: 'No se pudo iniciar la llamada de alarma' });
              return;
      }

      res.status(200).json({ ok: true, callSid: data.sid });
  } catch (err) {
        console.error('Error llamando a Twilio:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
  }
}
