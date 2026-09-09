import { useEffect, useState } from 'react'

import { formatMoneyOrDash, formatPct } from '../../utils/format'

import { colorForService, OTHER_COLOR } from '../../utils/serviceStyle'

const MAX_COLUMN_HEIGHT = 200

const TOP_N = 6

function bucketMonth(month) {
  const items = Array.isArray(month.items) ? month.items : []

  const sorted = items
    .slice()
    .sort((a, b) => (b.amount ?? 0) - (a.amount ?? 0))

  const top = sorted.slice(0, TOP_N)

  const otherAmount = sorted
    .slice(TOP_N)
    .reduce((sum, item) => sum + (item.amount ?? 0), 0)

  const total = sorted.reduce((sum, item) => sum + (item.amount ?? 0), 0)

  const segments = [
    ...top.map((item) => ({
      name: item.key,
      amount: item.amount ?? 0,
      color: colorForService(item.key),
    })),
    ...(otherAmount > 0
      ? [{ name: 'Other', amount: otherAmount, color: OTHER_COLOR }]
      : []),
  ]

  return { month: month.month, total, segments }
}

export default function MonthlyCostBreakdownChart({
  monthly,
  emptyMessage = 'No monthly cost data is available yet.',
}) {
  const [mounted, setMounted] = useState(false)
  const [hover, setHover] = useState(null) // { monthKey, name, amount, pct }

  const months = (Array.isArray(monthly) ? monthly : []).map(bucketMonth)

  const maxTotal = Math.max(...months.map((month) => month.total), 1)

  useEffect(() => {
    const frame = requestAnimationFrame(() => setMounted(true))
    return () => cancelAnimationFrame(frame)
  }, [monthly])

  if (!months.length || maxTotal <= 1) {
    return (
      <div className="stack-empty">
        <span>&#9633;</span>
        {emptyMessage}
      </div>
    )
  }

  // Legend ranks services by their combined weight across every
  // visible month, not just the most recent one -- a service that
  // spiked once shouldn't outrank one that's steadily #1 all period.
  const totals = new Map()
  let grandTotal = 0

  for (const month of months) {
    for (const segment of month.segments) {
      totals.set(segment.name, {
        amount: (totals.get(segment.name)?.amount || 0) + segment.amount,
        color: segment.color,
      })
      grandTotal += segment.amount
    }
  }

  const legend = Array.from(totals.entries())
    .map(([name, { amount, color }]) => ({
      name,
      color,
      amount,
      pct: grandTotal ? (amount / grandTotal) * 100 : 0,
    }))
    .sort((a, b) => (a.name === 'Other' ? 1 : b.amount - a.amount))

  return (
    <div className="stack-chart">
      <div className="stack-columns">
        {months.map((month, monthIndex) => (
          <div className="stack-col-wrap" key={month.month}>
            <div
              className="stack-col"
              style={{
                height: mounted
                  ? `${Math.max(6, (month.total / maxTotal) * MAX_COLUMN_HEIGHT)}px`
                  : '0px',
                transitionDelay: `${monthIndex * 55}ms`,
              }}
            >
              {month.segments.map((segment, segIndex) => {
                const pct = month.total
                  ? (segment.amount / month.total) * 100
                  : 0

                const key = `${month.month}-${segment.name}`

                return (
                  <div
                    key={segment.name}
                    className="stack-seg"
                    tabIndex={0}
                    style={{
                      flex: `${Math.max(segment.amount, 0.01)} 0 0`,
                      background: segment.color,
                    }}
                    onMouseEnter={() =>
                      setHover({
                        key,
                        name: segment.name,
                        amount: segment.amount,
                        pct,
                      })
                    }
                    onFocus={() =>
                      setHover({
                        key,
                        name: segment.name,
                        amount: segment.amount,
                        pct,
                      })
                    }
                    onMouseLeave={() => setHover(null)}
                    onBlur={() => setHover(null)}
                  />
                )
              })}
            </div>

            {hover && month.segments.some((s) => `${month.month}-${s.name}` === hover.key) && (
              <div className="stack-tooltip">
                <strong>{hover.name}</strong>
                <span>{formatMoneyOrDash(hover.amount)}</span>
                <small>{formatPct(hover.pct)} of month</small>
              </div>
            )}

            <span className="stack-month-label mono">{month.month}</span>
            <span className="stack-month-total mono">
              {formatMoneyOrDash(month.total)}
            </span>
          </div>
        ))}
      </div>

      
    </div>
  )
}
