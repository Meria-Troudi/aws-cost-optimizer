import { useEffect, useState } from 'react'

import {
  formatMoneyOrDash,
  formatMoneyOrUnavailable,
  formatPct,
} from '../utils/format'

import { serviceStyle } from '../utils/serviceStyle'

const PAGE_SIZE = 5
 
export default function CostDriverList({ drivers }) {
  const [expanded, setExpanded] = useState(null)
  const [page, setPage] = useState(1)

  const rows = Array.isArray(drivers) ? drivers : []

  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  const safePage = Math.min(page, totalPages)
  const pagedRows = rows.slice(
    (safePage - 1) * PAGE_SIZE,
    safePage * PAGE_SIZE,
  )

  useEffect(() => {
    setPage(1)
  }, [drivers])

  function goPage(next) {
    setPage(Math.min(Math.max(1, next), totalPages))
  }

  if (!rows.length) {
    return (
      <div className="chart-empty">
        No cost-driver data is available for this scan.
      </div>
    )
  }

  return (
    <div className="cost-driver-table">
      <div className="cost-driver-table-head">
        <span />
        <span>Service</span>
        <span>Cost</span>
        <span>Share</span>
        <span>Trend</span>
        <span />
      </div>

      {pagedRows.map((row) => {
        const name = row.service || 'AWS service'
        const isOpen = expanded === name
        const style = serviceStyle(name)
        const usageTypes = Array.isArray(row.usage_types)
          ? row.usage_types
          : []

        return (
          <div
            className={`cost-driver-table-group ${isOpen ? 'open' : ''}`}
            key={name}
          >
            <button
              type="button"
              className="cost-driver-table-row"
              onClick={() => setExpanded(isOpen ? null : name)}
              aria-expanded={isOpen}
            >
              <span
                className="cost-driver-table-avatar"
                style={{ background: style.color }}
              >
                {style.icon}
              </span>

              <span className="cost-driver-table-name">
                <strong>{name}</strong>
                <span className="cost-driver-table-rank mono">
                   {String(row.rank ?? '').padStart(2, '0')}
                </span>
              </span>

              <span className="mono cost-driver-table-cost">
                {formatMoneyOrDash(row.cost)}
              </span>

              <span className="mono cost-driver-table-share">
                {formatPct(row.share_pct)}
              </span>

              <span
                className={
                  row.trend === 'increased'
                    ? 'up'
                    : row.trend === 'decreased'
                      ? 'down'
                      : 'cost-driver-table-trend-flat'
                }
              >
                {row.change_percentage != null
                  ? formatPct(row.change_percentage, true)
                  : '—'}
              </span>

              <span className="row-chevron">
                {isOpen ? '⌃' : '⌄'}
              </span>
            </button>

            {isOpen && (
              <div className="cost-driver-usage-list">
                {!usageTypes.length && (
                  <div className="cost-driver-usage-empty">
                    No usage-type breakdown available.
                  </div>
                )}

                {usageTypes.map((item) => (
                  <div
                    className="cost-driver-usage-row"
                    key={item.usage_type}
                  >
                    <span>{item.usage_type}</span>
                    <span className="mono">
                      {formatMoneyOrUnavailable(item.cost)}
                    </span>
                    <span className="cost-driver-usage-pct">
                      {formatPct(item.share_pct)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })}

      <div className="cost-explorer-pager">
        <button
          type="button"
          className="small-btn"
          onClick={() => goPage(safePage - 1)}
          disabled={safePage <= 1}
        >
          ← 
        </button>

        <span className="cost-explorer-pager-info mono">
          Page {safePage} of {totalPages} ·{' '}
          {rows.length}{' '}
          {rows.length === 1 ? 'service' : 'services'}
        </span>

        <button
          type="button"
          className="small-btn"
          onClick={() => goPage(safePage + 1)}
          disabled={safePage >= totalPages}
        >
           →
        </button>
      </div>
    </div>
  )
}
