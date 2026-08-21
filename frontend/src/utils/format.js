export function formatMoneyOrDash(
  value,
) {
  if (
    value === null ||
    value === undefined ||
    value === '' ||
    !Number.isFinite(
      Number(value),
    )
  ) {
    return '—'
  }

  return new Intl.NumberFormat(
    'en-US',
    {
      style: 'currency',
      currency: 'USD',
      maximumFractionDigits: 2,
    },
  ).format(Number(value))
}

export function formatMoneyOrUnavailable(
  value,
) {
  if (
    value === null ||
    value === undefined ||
    value === '' ||
    !Number.isFinite(
      Number(value),
    )
  ) {
    return 'Cost unavailable'
  }

  return formatMoneyOrDash(value)
}

export function formatCompact(
  value,
) {
  if (
    value === null ||
    value === undefined ||
    !Number.isFinite(
      Number(value),
    )
  ) {
    return '—'
  }

  const number = Number(value)

  if (Math.abs(number) >= 1000000) {
    return `${(
      number / 1000000
    ).toFixed(1)}M`
  }

  if (Math.abs(number) >= 1000) {
    return `${(
      number / 1000
    ).toFixed(1)}k`
  }

  return number.toFixed(0)
}

export function formatChange(
  value,
) {
  if (
    value === null ||
    value === undefined ||
    !Number.isFinite(
      Number(value),
    )
  ) {
    return '—'
  }

  const number = Number(value)

  if (number > 0) {
    return `+${formatMoneyOrDash(
      number,
    )}`
  }

  return formatMoneyOrDash(
    number,
  )
}

export function formatPct(
  value,
  withSign = false,
) {
  if (
    value === null ||
    value === undefined ||
    !Number.isFinite(
      Number(value),
    )
  ) {
    return '—'
  }

  const number = Number(value)

  const formatted = `${Math.abs(
    number,
  ).toFixed(1)}%`

  if (!withSign) {
    return `${number >= 0 ? '' : '-'}${formatted}`
  }

  if (number > 0) {
    return `+${formatted}`
  }

  if (number < 0) {
    return `-${formatted}`
  }

  return '0.0%'
}

export function formatDate(
  value,
) {
  if (!value) return '—'

  const date =
    new Date(value)

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return String(value)
  }

  return new Intl.DateTimeFormat(
    'en-GB',
    {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
    },
  ).format(date)
}

export function formatDateTime(
  value,
) {
  if (!value) return '—'

  const date =
    new Date(value)

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return String(value)
  }

  return new Intl.DateTimeFormat(
    'en-GB',
    {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    },
  ).format(date)
}

export function sevLabel(
  severity,
) {
  const value = String(
    severity || 'low',
  ).toLowerCase()

  if (value === 'critical') {
    return 'Critical'
  }

  if (value === 'high') {
    return 'High'
  }

  if (value === 'medium') {
    return 'Medium'
  }

  return 'Low'
}

export function sevClass(
  severity,
) {
  const value = String(
    severity || 'low',
  ).toLowerCase()

  if (value === 'critical') {
    return 'sev-critical'
  }

  if (value === 'high') {
    return 'sev-high'
  }

  if (value === 'medium') {
    return 'sev-medium'
  }

  return 'sev-low'
}

export function statusLabel(
  status,
) {
  if (
    status === null ||
    status === undefined ||
    status === ''
  ) {
    return 'Unknown'
  }

  const value = String(
    status,
  )
    .replaceAll('_', ' ')
    .trim()

  return value
    .charAt(0)
    .toUpperCase() +
    value.slice(1)
}

export function pluralize(
  count,
  singular,
  plural = `${singular}s`,
) {
  const number = Number(count) || 0

  return `${number} ${
    number === 1 ? singular : plural
  }`
}

export function truncateId(
  value,
  maxLength = 20,
) {
  if (!value) return '—'

  const text = String(value)

  if (
    text.length <= maxLength
  ) {
    return text
  }

  const side = Math.floor(
    (maxLength - 3) / 2,
  )

  return `${text.slice(
    0,
    side,
  )}...${text.slice(
    -side,
  )}`
}