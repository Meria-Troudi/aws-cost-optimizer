const API_BASE = (
  import.meta.env.VITE_API_BASE ?? ''
).replace(/\/$/, '')

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`

  const headers = {
    Accept: 'application/json',
    ...options.headers,
  }

  if (
    options.body != null &&
    !headers['Content-Type']
  ) {
    headers['Content-Type'] = 'application/json'
  }

  let response

  try {
    response = await fetch(url, {
      ...options,
      headers,
    })
  } catch (err) {
    throw new Error(
      `Cannot reach the backend. Start the API server on port 8000. (${err.message})`,
    )
  }

  const contentType =
    response.headers.get('content-type') || ''

  let body = null

  if (response.status !== 204) {
    try {
      if (
        contentType.includes(
          'application/json',
        )
      ) {
        body = await response.json()
      } else {
        const text = await response.text()
        body = text || null
      }
    } catch {
      body = null
    }
  }

  if (!response.ok) {
    let detail = 'Request failed'

    if (body?.detail != null) {
      detail = body.detail
    } else if (body?.message != null) {
      detail = body.message
    } else if (
      typeof body === 'string' &&
      body.trim()
    ) {
      detail = body
    }

    if (Array.isArray(detail)) {
      detail = detail
        .map(
          item =>
            item?.msg ||
            JSON.stringify(item),
        )
        .join(', ')
    }

    throw new Error(
      typeof detail === 'string'
        ? detail
        : JSON.stringify(detail),
    )
  }

  return body
}

function buildQuery(params = {}) {
  const clean = Object.fromEntries(
    Object.entries(params).filter(
      ([, value]) =>
        value !== undefined &&
        value !== null &&
        value !== '',
    ),
  )

  return new URLSearchParams(
    clean,
  ).toString()
}

export function checkApi() {
  return request('/health')
}

export function getAccount() {
  return request('/api/account')
}

export function getCostRegions() {
  return request('/api/cost/regions')
}

export function getDashboard(
  params = {},
) {

  const query = buildQuery(
    params,
  )

  return request(
    `/api/dashboard/overview${
      query ? `?${query}` : ''
    }`,
  )
}

export function getCostExplorer(
  params = {},
) {

  const query = buildQuery(
    params,
  )

  return request(
    `/api/cost/explorer${
      query ? `?${query}` : ''
    }`,
  )
}

export function getCostExplorerService(
  params = {},
) {

  const query = buildQuery(
    params,
  )

  return request(
    `/api/cost/explorer/service${
      query ? `?${query}` : ''
    }`,
  )
}

export function startScan(
  payload = {},
) {

  return request(
    '/api/scans',
    {
      method: 'POST',
      body: JSON.stringify(
        payload,
      ),
    },
  )
}

export function getScans(
  params = {},
) {

  const query = buildQuery(
    params,
  )

  return request(
    `/api/scans${
      query ? `?${query}` : ''
    }`,
  )
}

export function getScan(scanId) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}`,
  ).then(
    response =>
      response?.scan ??
      response,
  )
}

export function getScanCostSummary(
  scanId,
) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}/cost-summary`,
  )
}

export function getScanCostDrivers(
  scanId,
) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}/cost-drivers`,
  )
}

export function getScanCollectionSummary(
  scanId,
) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}/collection-summary`,
  )
}

export function deleteScan(
  scanId,
) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}`,
    {
      method: 'DELETE',
    },
  )
}

export function getFindings(
  scanId,
) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}/findings`,
  )
}

export function getRecommendations(
  scanId,
) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}/recommendations`,
  )
}

export function getCostTrend(
  scanId,
) {

  if (!scanId) {
    throw new Error(
      'Scan ID is required.',
    )
  }

  return request(
    `/api/scans/${encodeURIComponent(
      scanId,
    )}/cost-trend`,
  )
}

export function getRecommendation(
  recommendationId,
) {

  if (!recommendationId) {
    throw new Error(
      'Recommendation ID is required.',
    )
  }

  return request(
    `/api/recommendations/${encodeURIComponent(
      recommendationId,
    )}`,
  )
}

export function explainRecommendation(
  recommendationId,
  { force = false } = {},
) {

  if (!recommendationId) {
    throw new Error(
      'Recommendation ID is required.',
    )
  }

  const query = buildQuery({
    force: force ? 'true' : undefined,
  })

  return request(
    `/api/recommendations/${encodeURIComponent(
      recommendationId,
    )}/explain${
      query ? `?${query}` : ''
    }`,
    {
      method: 'POST',
    },
  )
}