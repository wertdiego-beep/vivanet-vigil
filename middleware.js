// Filtro en el borde (Vercel Edge) — primera capa anti-scraping / anti-bot.
// Bloquea herramientas de scraping conocidas SIN afectar a usuarios reales (navegadores).
// Los datos sensibles ya están protegidos por autenticación en /api.

export const config = {
  // Aplica a todo menos los recursos estáticos necesarios para que la PWA cargue.
  matcher: ['/((?!_next/|favicon\\.ico|manifest\\.json|icon-|sw\\.js).*)'],
};

const BLOQUEADOS = [
  'python-requests', 'python-urllib', 'scrapy', 'curl/', 'wget/', 'libwww',
  'go-http-client', 'httpclient', 'java/', 'okhttp', 'aiohttp', 'httpx',
  'phantomjs', 'headlesschrome', 'puppeteer', 'playwright', 'selenium',
  'httrack', 'wpscan', 'nikto', 'sqlmap', 'masscan', 'zgrab', 'nmap',
  'crawler', 'spider', 'scraper', 'harvest', 'scan',
];

export default function middleware(request) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  // UA vacío o de herramienta de scraping conocida -> bloquear.
  const esBot = !ua || BLOQUEADOS.some((b) => ua.includes(b));
  if (esBot) {
    return new Response(
      '403 — Acceso no autorizado. Este servicio es propiedad de Vivanet Spa y no permite acceso automatizado.',
      { status: 403, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } }
    );
  }
  // Usuario real -> continúa normal.
  return;
}
