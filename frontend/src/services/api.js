const API_BASE = '/api/v1';

async function handleResponse(response) {
  if (!response.ok) {
    let errorMsg = `Server error (${response.status})`;
    try {
      const errorData = await response.json();
      errorMsg = errorData.detail || errorMsg;
    } catch {
      // Fallback to status text
    }
    throw new Error(errorMsg);
  }
  if (response.status === 204) return null;
  return response.json();
}

export const api = {
  async checkHealth() {
    const res = await fetch('/api/health');
    return handleResponse(res);
  },

  async getStats() {
    const res = await fetch(`${API_BASE}/stats/`);
    return handleResponse(res);
  },

  async getHistory(limit = 50) {
    const res = await fetch(`${API_BASE}/history/?limit=${limit}`);
    return handleResponse(res);
  },

  async getScanDetail(id) {
    const res = await fetch(`${API_BASE}/history/${id}`);
    return handleResponse(res);
  },

  async deleteScan(id) {
    const res = await fetch(`${API_BASE}/history/${id}`, {
      method: 'DELETE',
    });
    return handleResponse(res);
  },

  async scanMessage(message, sourceType = 'auto') {
    const res = await fetch(`${API_BASE}/scan/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, source_type: sourceType }),
    });
    return handleResponse(res);
  },

  async scanUrl(url) {
    const res = await fetch(`${API_BASE}/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return handleResponse(res);
  },
};
