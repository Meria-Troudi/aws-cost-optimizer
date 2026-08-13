import { formatMoneyOrDash, formatPct } from '../../utils/format'
import { serviceStyle } from '../../utils/serviceStyle'

export default function CostByServiceGrid({ services, limit = 4 }) {
  const rows = (services || []).slice(0, limit)
  if (!rows.length) return null

  return (
    <div className="panel">
      <div className="panel-head">
        <div className="panel-title">Cost by Service</div>
        <div className="panel-icon-btn">⋯</div>
      </div>
      <div className="svc-grid">
        {rows.map((row) => {
          const style = serviceStyle(row.service_short || row.service)
          return (
            <div className="svc-card" key={row.service}>
              <div className="svc-ico" style={{ background: style.color }}>
                {style.icon}
              </div>
              <div className="svc-name">{row.service_short || row.service}</div>
              <div className="svc-cost mono">{formatMoneyOrDash(row.current_cost ?? row.cost)}</div>
              {row.change_pct != null && (
                <div className={`svc-change ${row.change_pct >= 0 ? 'up' : 'down'}`}>
                  {formatPct(row.change_pct, true)}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
