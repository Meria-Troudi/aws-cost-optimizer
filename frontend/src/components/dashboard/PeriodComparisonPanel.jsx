import { formatMoneyOrDash } from '../../utils/format'

function PeriodCard({ periodData, accent }) {
  if (!periodData) return null
  const {
    month,
    label,
    total_spend,
    top_services,
    top_regions,
    services_with_spend,
    regions_with_spend,
  } = periodData

  const hasSpend = Number(total_spend) > 0

  return (
    <div className={`period-card ${accent || ''}`}>
      <div className="period-head">
        <div className="period-label">{label}</div>
        <div className="period-month mono">{month}</div>
      </div>
      <div className="period-total mono">
        {hasSpend ? formatMoneyOrDash(total_spend) : '—'}
      </div>
      <div className="period-summary-row">
        <div className="period-summary-item">
          <span className="period-summary-k">Services</span>
          <span className="period-summary-v mono">{services_with_spend ?? 0}</span>
        </div>
        <div className="period-summary-item">
          <span className="period-summary-k">Regions</span>
          <span className="period-summary-v mono">{regions_with_spend ?? 0}</span>
        </div>
      </div>

      {top_services && top_services.length > 0 && (
        <div className="period-section">
          <div className="period-section-title">Top Services</div>
          <ul className="period-list">
            {top_services.map((s) => (
              <li key={s.service} className="period-list-row">
                <span className="period-list-rank mono">{s.rank}</span>
                <span className="period-list-name">
                  {s.service?.replace('Amazon ', '').replace('AWS ', '')}
                </span>
                <span className="period-list-cost mono">
                  {formatMoneyOrDash(s.cost)}
                </span>
                <span className="period-list-share">{(s.share_pct ?? 0).toFixed(0)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {top_regions && top_regions.length > 0 && (
        <div className="period-section">
          <div className="period-section-title">Top Regions</div>
          <ul className="period-list">
            {top_regions.map((r) => (
              <li key={r.region} className="period-list-row">
                <span className="period-list-rank mono">{r.rank}</span>
                <span className="period-list-name">{r.region}</span>
                <span className="period-list-cost mono">
                  {formatMoneyOrDash(r.cost)}
                </span>
                <span className="period-list-share">{(r.share_pct ?? 0).toFixed(0)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {!hasSpend && (
        <div className="period-empty">
          No cost data collected for this month
        </div>
      )}
    </div>
  )
}

export default function PeriodComparisonPanel({ periodComparison }) {
  if (!periodComparison) return null

  const current = periodComparison.current_month
  const threeAgo = periodComparison.three_months_ago
  const sixAgo = periodComparison.six_months_ago

  const periods = [
    { data: sixAgo, accent: 'slate' },
    { data: threeAgo, accent: 'white' },
    { data: current, accent: 'blue' },
  ]

  return (
    <div className="panel section-gap period-comparison">
      <div className="panel-head">
        <div>
          <div className="panel-title">Period Comparison</div>
          <div className="panel-sub">
            Side-by-side spend breakdown: current month vs. 3 months ago vs. 6 months ago
          </div>
        </div>
      </div>
      <div className="period-grid">
        {periods.map((p, idx) => (
          <PeriodCard key={idx} periodData={p.data} accent={p.accent} />
        ))}
      </div>
    </div>
  )
}
