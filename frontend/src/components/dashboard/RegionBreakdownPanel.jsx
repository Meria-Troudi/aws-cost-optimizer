import { formatMoneyOrDash, formatPct } from '../../utils/format'

export default function RegionBreakdownPanel({ regionCosts }) {
  if (!regionCosts?.length) {
    return (
      <div className="panel">
        <div className="panel-head">
          <div className="panel-title">Regional Spend</div>
        </div>
        <div className="chart-empty">No regional cost data</div>
      </div>
    )
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-title">Regional Spend</div>
        <div className="panel-icon-btn">⋯</div>
      </div>
      <div className="region-list">
        {regionCosts.slice(0, 6).map((row) => (
          <div className="region-list-row" key={row.region}>
            <div>
              <div className="region-list-name">{row.region}</div>
              <div className="region-list-share">{row.share_pct?.toFixed(1)}% of period</div>
            </div>
            <div className="region-list-right">
              <div className="region-list-cost mono">{formatMoneyOrDash(row.cost)}</div>
              {row.change_pct != null && (
                <div className={`region-list-change ${row.change_pct >= 0 ? 'up' : 'down'}`}>
                  {formatPct(row.change_pct, true)}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
