export function subscribeToAlertStream(onAlert, onError) {
  const url = 'http://localhost:8000/api/v1/stream/alerts';
  const eventSource = new EventSource(url);

  eventSource.addEventListener('alert', (event) => {
    try {
      const alertData = JSON.parse(event.data);
      onAlert(alertData);
    } catch (err) {
      console.error('Error parsing SSE alert payload:', err);
    }
  });

  eventSource.addEventListener('ping', () => {
    // Heartbeat
  });

  eventSource.onerror = (err) => {
    console.warn('SSE stream disconnected or retrying:', err);
    if (onError) onError(err);
  };

  return () => {
    eventSource.close();
  };
}