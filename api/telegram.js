// Función serverless de Vercel: /api/telegram
// Envía mensajes o ubicaciones por Telegram (central y contactos de emergencia),
// manteniendo el token del bot oculto en el servidor (variable de entorno TELEGRAM_BOT_TOKEN).

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
  }

  const { chatId, texto, lat, lng } = req.body || {};

  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) {
    res.status(500).json({ error: 'Falta configurar TELEGRAM_BOT_TOKEN en Vercel' });
    return;
  }

  if (!chatId) {
    res.status(400).json({ error: 'Falta el chat_id de destino' });
    return;
  }

  const esUbicacion = typeof lat === 'number' && typeof lng === 'number';

  if (!esUbicacion && !texto) {
    res.status(400).json({ error: 'Falta el texto del mensaje' });
    return;
  }

  const metodo = esUbicacion ? 'sendLocation' : 'sendMessage';
  const cuerpo = esUbicacion
    ? { chat_id: chatId, latitude: lat, longitude: lng }
    : { chat_id: chatId, text: texto };

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/${metodo}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cuerpo)
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Error de Telegram:', response.status, data);
      res.status(502).json({ error: 'No se pudo enviar la notificación de Telegram' });
      return;
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Error llamando a Telegram:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
}
