// Función serverless de Vercel: /api/chat
// Recibe el mensaje del usuario desde el chat de SOS360 y responde usando Gemini,
// manteniendo la clave de la API oculta en el servidor (variable de entorno GEMINI_API_KEY).

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método no permitido' });
    return;
}

  const { mensaje, contexto } = req.body || {};

  if (!mensaje || typeof mensaje !== 'string') {
    res.status(400).json({ error: 'Falta el mensaje' });
    return;
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: 'Falta configurar GEMINI_API_KEY en Vercel' });
    return;
  }

  const systemPrompt =
    'Eres el asistente virtual de SOS360, una app de seguridad y monitoreo para locales comerciales en Chile. ' +
    'Ayudas con dudas sobre alarmas, cámaras y sensores, puedes sugerir crear un ticket de soporte o agendar una visita técnica, ' +
    'y respondes de forma breve, clara y amable, en español de Chile. ' +
    'No inventes datos que no tengas: si no sabes algo específico del sistema del usuario, dilo y ofrece crear un ticket de soporte. ' +
    (contexto ? `Datos conocidos del local del usuario: ${contexto}` : 'No se conocen datos adicionales del local del usuario.');

  try {
    const response = await fetch(
                  `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-lite-latest:generateContent?key=${apiKey}`,
{
          method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                                contents: [{ parts: [{ text: mensaje }] }],
                                systemInstruction: { parts: [{ text: systemPrompt }] }
})
  }
        );

    if (!response.ok) {
      const errText = await response.text();
      console.error('Error de Gemini:', response.status, errText);
      res.status(502).json({ error: 'La IA no pudo responder en este momento' });
      return;
    }

    const data = await response.json();
    const respuesta =
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      'No pude generar una respuesta, intenta de nuevo.';

    res.status(200).json({ respuesta });
} catch (err) {
    console.error('Error llamando a Gemini:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
}
}
