// Service Worker de Vigil: permite instalar la app y usarla sin conexión
// para lo básico (la pantalla ya cargada). Los datos en vivo (Firestore,
// chat IA, Telegram) siempre requieren internet.

const CACHE_NAME = 'vigil-cache-v1';
const APP_SHELL = [
  '/',
  '/index.html',
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
