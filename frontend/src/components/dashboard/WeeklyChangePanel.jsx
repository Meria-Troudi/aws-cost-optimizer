import { useEffect, useState } from 'react'

import { getWeeklyServiceChanges } from '../../api/client'

import { formatChange, formatPct } from '../../utils/format'

import { colorForService } from '../../utils/serviceStyle'

export default function WeeklyChangePanel() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true

    getWeeklyServiceChanges({ limit: 6 })
      .then((response) => {
        if (!active) return
        setData(response)
      })
      .catch((err) => {
        if (!active) return
        setError(err.message || 'Unable to load weekly service changes.')
      })
      .finally(() => {
        if (!active) return
        setLoading(false)
      })

    return () => {
      active = false
    }
  }, [])

  const rows = [
    ...(Array.isArray(data?.items) ? data.items : []),
    ...(data?.others ? [data.others] : []),
  ]

  const maxAbsPct = rows.reduce((max, row) => {
    if (row.change_pct == null) return max
    return Math.max(max, Math.abs(row.change_pct))
  }, 1)

  return (
    <section className="panel weekly-change-panel">
      <div className="panel-head">
        <div>
          <div className="eyebrow">/ Weekly Change</div>

          <h2 className="panel-title">Top services, week over week</h2>

          <p className="panel-sub">
            {data?.current_period?.label || 'Last 7 days'} vs{' '}
            {data?.previous_period?.label || 'previous 7 days'}.
          </p>
        </div>
      </div>

      {error ? (
        <div className="page-error">{error}</div>
      ) : loading && !data ? (
        <div className="chart-empty">
          <span className="chart-empty-icon">&#8644;</span>
          <strong>Loading&hellip;</strong>
        </div>
      ) : !rows.length ? (
        <div className="chart-empty">
          <span className="chart-empty-icon">&#8644;</span>
          <strong>No week-over-week cost data yet.</strong>
        </div>
      ) : (
        <div className="weekly-change-rows">
          {rows.map((row) => {
            const isNew = row.change_pct == null
            const isPositive = (row.change_amount ?? 0) >= 0
            const widthPct = isNew
              ? 6
              : Math.min(50, (Math.abs(row.change_pct) / maxAbsPct) * 50)

            return (
              <div className="weekly-change-row" key={row.service}>
                <div className="weekly-change-name">
                  <span
                    className="weekly-change-dot"
                    style={{ background: colorForService(row.service) }}
                  />
                  <span>{row.service}</span>
                </div>

                <div className="weekly-change-track">
                  <span className="weekly-change-zero" />

                  <div
                    className={`weekly-change-bar ${isPositive ? 'positive' : 'negative'}`}
                    style={
                      isPositive
                        ? { left: '50%', width: `${widthPct}%` }
                        : { right: '50%', width: `${widthPct}%` }
                    }
                  />
                </div>

                <div className="weekly-change-value mono">
                  {formatChange(row.change_amount)}
                  {isNew ? (
                    <small>new</small>
                  ) : (
                    <small>{formatPct(row.change_pct, true)}</small>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}
