// Same-origin API: the dashboard is served by the FastAPI app (Vite dev proxies /api).
const BASE = '/api/v1';

export async function getJSON(path, fallback = null) {
  try {
    const res = await fetch(`${BASE}${path}`);
    if (!res.ok) return fallback;
    return await res.json();
  } catch {
    return fallback;
  }
}

export function subscribe({ onAlert, onReset, onOpen, onError }) {
  const es = new EventSource(`${BASE}/stream/alerts`);
  es.addEventListener('alert', (e) => { try { onAlert(JSON.parse(e.data)); } catch { /* malformed event */ } });
  es.addEventListener('reset', (e) => { try { onReset(JSON.parse(e.data)); } catch { onReset({}); } });
  es.onopen = () => onOpen?.();
  es.onerror = () => onError?.();
  return () => es.close();
}
