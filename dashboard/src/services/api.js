const BASE_URL = 'http://localhost:8000/api/v1';

export async function fetchHealth() {
  try {
    const res = await fetch(`${BASE_URL}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return await res.json();
  } catch (err) {
    console.error('API Error (health):', err);
    return { status: 'OFFLINE', monitoring: 'DISCONNECTED', active: false };
  }
}

export async function fetchMetrics() {
  try {
    const res = await fetch(`${BASE_URL}/metrics`);
    if (!res.ok) throw new Error('Metrics fetch failed');
    return await res.json();
  } catch (err) {
    console.error('API Error (metrics):', err);
    return { active_flows: 0, packets_per_sec: 0, bytes_per_sec: 0, total_alerts: 0, mode: 'OFFLINE' };
  }
}

export async function fetchAlerts(threatClass = null, severity = null, limit = 100) {
  try {
    const params = new URLSearchParams();
    if (threatClass) params.append('threat_class', threatClass);
    if (severity) params.append('severity', severity);
    params.append('limit', limit);

    const res = await fetch(`${BASE_URL}/alerts?${params.toString()}`);
    if (!res.ok) throw new Error('Alerts fetch failed');
    return await res.json();
  } catch (err) {
    console.error('API Error (alerts):', err);
    return { count: 0, alerts: [] };
  }
}