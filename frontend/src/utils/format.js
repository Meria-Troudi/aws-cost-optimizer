export function formatMoney(value) {
  if (value == null || Number.isNaN(value)) return 'Not estimated'
  return `$${value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
}

export function formatMoneyOrDash(value) {
  if (value == null || Number.isNaN(value)) return '—'
  return formatMoney(value)
}

export function formatPct(value, signed = false) {
  if (value == null || Number.isNaN(value)) return '—'
  const prefix = signed && value > 0 ? '+' : signed && value < 0 ? '' : ''
  return `${prefix}${value.toFixed(1)}%`
}

export function formatChange(value) {
  if (value == null || Number.isNaN(value)) return '—'
  const prefix = value >= 0 ? '+' : '-'
  return `${prefix}$${Math.abs(value).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
}

export function sevClass(severity) {
  const s = (severity || 'low').toLowerCase()
  if (s === 'high') return 'sev-high'
  if (s === 'medium') return 'sev-medium'
  return 'sev-low'
}

export function statusLabel(status) {
  if (!status) return 'Pending review'
  return status.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function sevLabel(severity) {
  const s = (severity || 'low').toLowerCase()
  if (s === 'medium') return 'Med'
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export function formatCompact(value) {
  if (value == null || Number.isNaN(value)) return '—'
  const n = Number(value)
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return n.toFixed(0)
}

export function formatDate(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })
}

export function formatDateTime(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatMonthLabel(key) {
  if (!key) return '—'
  const [year, month] = key.split('-')
  const names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  return `${names[Number(month) - 1]} ${year.slice(2)}`
}

export function truncateId(id, len = 12) {
  if (!id) return '—'
  if (id.length <= len) return id
  return `${id.slice(0, len)}…`
}
