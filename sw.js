// Service Worker de SOS360: permite instalar la app y usarla sin conexión
// para lo básico, y recibir notificaciones push (Firebase Cloud Messaging)
// aunque la app esté cerrada. Los datos en vivo (Firestore, chat IA, Telegram)
// siempre requieren internet.
//
// IMPORTANTE: el HTML de la app (navegación) usa estrategia "red primero":
// siempre pide la versión más nueva al servidor, y solo usa la copia
// guardada si no hay conexión. Así, cuando subimos cambios a la app,
// los usuarios los ven de inmediato en vez de quedarse con una versión vieja.

importScripts('https://www.gstatic.com/firebasejs/10.7.1/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.7.1/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyCRAFZXVB6VZ8vAVoMF3WDvjcmUCiInP2g",
  authDomain: "vivanet-f8ac2.firebaseapp.com",
  projectId: "vivanet-f8ac2",
  storageBucket: "vivanet-f8ac2.firebasestorage.app",
  messagingSenderId: "553479199763",
  appId: "1:553479199763:web:d7004add8e769bbc2b73e6"
});

const messaging = firebase.messaging();

// Cuando llega un push y la app está cerrada o en segundo plano,
// mostramos una notificación del sistema.
messaging.onBackgroundMessage((payload) => {
  const titulo = payload.notification?.title || 'SOS360';
  const cuerpo = payload.notification?.body || '';
  self.registration.showNotification(titulo, {
    body: cuerpo,
    icon: '/icon-192.png',
    badge: '/icon-192.png'
  });
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((clientList) => {
      if (clientList.length > 0) return clientList[0].focus();
      return clients.openWindow('/');
    })
  );
});

const CACHE_NAME = 'sos360-cache-v8';
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
