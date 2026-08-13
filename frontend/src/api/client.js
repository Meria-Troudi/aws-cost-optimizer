const API_BASE = import.meta.env.VITE_API_BASE ?? ''

async function request(path, options = {}) {
  let response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
    })
  } catch (err) {
    throw new Error(
      `Cannot reach the backend. Start the API server (default port 8000). (${err.message})`,
    )
  }

  if (!response.ok) {
    let detail = 'Request failed'
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch {
      // ignore
    }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }

  if (response.status === 204) return null
  return response.json()
}

export function checkApi() {
  return request('/api/health')
}

export function getAccount() {
  return request('/api/account')
}

export function refreshCostData(payload = {}) {
  return request('/api/cost/refresh', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function getCostRegions() {
  return request('/api/cost/regions')
}

export function startScan(payload) {
  return request('/api/scans', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function getScan(scanId) {
  return request(`/api/scans/${scanId}`)
}

export function getFindings(scanId) {
  return request(`/api/scans/${scanId}/findings`)
}

export function getRecommendations(scanId) {
  return request(`/api/scans/${scanId}/recommendations`)
}

export function getCostTrend(scanId) {
  return request(`/api/scans/${scanId}/cost-trend`)
}

export function getDashboard(params = {}) {
  const qs = new URLSearchParams(params).toString()
  return request(`/api/dashboard${qs ? `?${qs}` : ''}`)
}
