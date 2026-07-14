// Función serverless de Vercel: /api/calle-gps
// Dado un punto GPS (lat/lng), devuelve la esquina real más cercana usando
// Overpass (OpenStreetMap) DESDE EL SERVIDOR, evitando el bloqueo CORS del
// navegador. Toma las dos calles reales más cercanas por distancia (no la
// "avenida importante" de la zona), y arma "Principal c/ Cruce".

function distanciaMetros(lat1, lon1, lat2, lon2) {
  const R = 6371000, toRad = (x) => x * Math.PI / 180;
  const dLat = toRad(lat2 - lat1), dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

function limpiarVia(nombre) {
  if (!nombre) return nombre;
  return nombre.replace(/^(Ciclov[ií]a|Ciclorruta|Ciclo\s*v[ií]a)\s+/i, '').trim();
}

const TIPOS_CALLE = new Set(['motorway', 'trunk', 'primary', 'secondary', 'tertiary', 'unclassified', 'residential', 'living_street', 'road']);

export default async function handler(req, res) {
  const lat = parseFloat(req.query.lat);
  const lng = parseFloat(req.query.lng);
  if (!isFinite(lat) || !isFinite(lng)) {
    res.status(400).json({ error: 'Faltan coordenadas' });
    return;
  }

  const consulta = `[out:json][timeout:15];way(around:170,${lat},${lng})[highway][name];out geom;`;
  const endpoints = [
    'https://overpass-api.de/api/interpreter',
    'https://overpass.kumi.systems/api/interpreter',
    'https://maps.mail.ru/osm/tools/overpass/api/interpreter'
  ];

  try {
    let data = null;
    for (const url of endpoints) {
      try {
        const r = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'data=' + encodeURIComponent(consulta)
        });
        if (r.ok) { data = await r.json(); break; }
      } catch (e) { /* probar el siguiente espejo */ }
    }
    if (!data) { res.status(200).json({ texto: null }); return; }

    const vias = (data.elements || []).filter((e) => e.type === 'way' && e.tags && e.tags.name && Array.isArray(e.geometry));

    const evaluadas = vias.map((v) => {
      let dmin = Infinity;
      for (const p of v.geometry) {
        const d = distanciaMetros(lat, lng, p.lat, p.lon);
        if (d < dmin) dmin = d;
      }
      return { nombre: limpiarVia(v.tags.name), tipo: v.tags.highway, dist: dmin, esCalle: TIPOS_CALLE.has(v.tags.highway) };
    });

    let pool = evaluadas.filter((v) => v.esCalle);
    if (!pool.length) pool = evaluadas;

    const porNombre = {};
    for (const v of pool) {
      if (!(v.nombre in porNombre) || v.dist < porNombre[v.nombre].dist) porNombre[v.nombre] = v;
    }
    const ordenadas = Object.values(porNombre).sort((a, b) => a.dist - b.dist);
    if (!ordenadas.length) { res.status(200).json({ texto: null }); return; }

    const principal = ordenadas[0];
    const cruce = ordenadas.find((v) => v.nombre !== principal.nombre);

    let texto = principal.nombre;
    if (cruce && cruce.dist < 130) texto += ' c/ ' + cruce.nombre;

    res.status(200).json({ texto, principal: principal.nombre, cruce: cruce ? cruce.nombre : null });
  } catch (err) {
    console.error('Error en calle-gps:', err);
    res.status(200).json({ texto: null });
  }
}
