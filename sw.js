// Service Worker de Vigil: permite instalar la app y usarla sin conexión
// para lo básico. Los datos en vivo (Firestore, chat IA, Telegram) siempre
// requieren internet.
//
// IMPORTANTE: el HTML de la app (navegación) usa estrategia "red primero":
// siempre pide la versión más nueva al servidor, y solo usa la copia
// guardada si no hay conexión. Así, cuando subimos cambios a la app,
// los usuarios los ven de inmediato en vez de quedarse con una versión vieja.

const CACHE_NAME = 'vigil-cache-v2';
const APP_SHELL = [
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Nunca cachear llamadas a la API (Gemini, Telegram, Twilio) ni a Firebase:
  // esas siempre deben ir a la red para no mostrar datos viejos.
  if (
    req.url.includes('/api/') ||
    req.url.includes('firestore.googleapis.com') ||
    req.url.includes('identitytoolkit.googleapis.com')
  ) {
    return;
  }

  // El documento HTML (la app en sí) siempre se pide a la red primero,
  // para que las actualizaciones se vean de inmediato. Si no hay internet,
  // usamos la última copia guardada como respaldo.
  if (req.mode === 'navigate' || (req.method === 'GET' && req.headers.get('accept')?.includes('text/html'))) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          return res;
        })
        .catch(() => caches.match(req))
    );
    return;
  }

  // Para el resto (íconos, manifest): copia guardada primero, más rápido.
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
          if (req.method === 'GET' && res.ok) {
            const resClone = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          }
          return res;
        })
        .catch(() => cached);
    })
  );
});
