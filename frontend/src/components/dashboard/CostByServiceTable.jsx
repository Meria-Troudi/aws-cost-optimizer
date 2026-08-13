import { formatChange, formatMoneyOrDash, formatPct } from '../../utils/format'

export default function CostByServiceTable({ services, limit = 12 }) {
  const rows = (services || []).slice(0, limit)
  if (!rows.length) return null

  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <div className="panel-title">Cost by Service</div>
          <div className="panel-sub">Latest month vs previous month</div>
        </div>
      </div>
      <div className="matrix-wrap">
        <table className="matrix-table cost-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Current</th>
              <th>Previous</th>
              <th>Change</th>
              <th>Share</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.service}>
                <td className="matrix-service">{row.service_short || row.service}</td>
                <td className="mono matrix-cell">{formatMoneyOrDash(row.current_cost)}</td>
                <td className="mono matrix-cell">{formatMoneyOrDash(row.previous_cost)}</td>
                <td className="mono matrix-cell">
                  {row.change_amount != null ? (
                    <span className={row.change_amount >= 0 ? 'up' : 'down'}>
                      {formatChange(row.change_amount)}
                      {row.change_pct != null && ` (${formatPct(row.change_pct, true)})`}
                    </span>
                  ) : (
                    '—'
                  )}
                </td>
                <td className="mono matrix-cell">{row.share_pct != null ? `${row.share_pct}%` : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
