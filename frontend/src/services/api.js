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

  async getHistory(params = {}) {
    let url = `${API_BASE}/history/`;
    // Backward compatibility if called with a single number limit
    if (typeof params === 'number') {
      url += `?limit=${params}`;
    } else {
      const query = new URLSearchParams();
      if (params.limit) query.append('limit', params.limit);
      if (params.scan_type && params.scan_type !== 'all') query.append('scan_type', params.scan_type);
      if (params.threat_level && params.threat_level !== 'all') query.append('threat_level', params.threat_level);
      if (params.search && params.search.trim()) query.append('search', params.search.trim());
      const qs = query.toString();
      if (qs) url += `?${qs}`;
    }
    const res = await fetch(url);
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

  async clearAllHistory() {
    const res = await fetch(`${API_BASE}/history/clear-all`, {
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
