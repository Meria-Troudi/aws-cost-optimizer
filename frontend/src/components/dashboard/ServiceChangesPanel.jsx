import { formatChange, formatMoneyOrDash, formatPct } from '../../utils/format'
import { serviceStyle } from '../../utils/serviceStyle'

function ChangeRow({ row, direction }) {
  const style = serviceStyle(row.service_short || row.service)
  const isUp = direction === 'up'
  const isNew = row.trend === 'new'
  return (
    <div className="change-row">
      <div className="change-row-left">
        <div className="change-row-icon" style={{ background: style.color }}>
          {isNew ? '★' : isUp ? '↑' : '↓'}
        </div>
        <div>
          <div className="change-row-name">{row.service_short || row.service}</div>
          <div className="change-row-sub mono">
            {isNew ? row.note || 'New this period' : `${formatMoneyOrDash(row.cost)} period total`}
          </div>
        </div>
      </div>
      <div className="change-row-right">
        <div className={`change-row-amt ${isUp || isNew ? 'up' : 'down'}`}>
          {formatChange(row.change_amount)}
        </div>
        {!isNew && (
          <div className={`change-row-pct ${isUp ? 'up' : 'down'}`}>
            {formatPct(row.change_pct, true)}
          </div>
        )}
      </div>
    </div>
  )
}

export default function ServiceChangesPanel({ serviceChanges }) {
  const increased = serviceChanges?.increased || []
  const decreased = serviceChanges?.decreased || []
  const newServices = serviceChanges?.new || []

  if (!increased.length && !decreased.length && !newServices.length) {
    return (
      <div className="panel section-gap">
        <div className="panel-head">
          <div className="panel-title">Service Changes</div>
        </div>
        <div className="chart-empty">Not enough monthly data to compute service changes.</div>
      </div>
    )
  }

  return (
    <div className="panel section-gap">
      <div className="panel-head">
        <div className="panel-title">Service Changes</div>
        <div className="panel-sub">Month-over-month spend movement by service</div>
      </div>
      <div className="changes-split">
        <div>
          <div className="changes-section-label up">Largest increases</div>
          {increased.length === 0 ? (
            <div className="changes-empty">No increases detected</div>
          ) : (
            increased.map((row) => (
              <ChangeRow key={row.service} row={row} direction="up" />
            ))
          )}
        </div>
        <div>
          <div className="changes-section-label down">Largest decreases</div>
          {decreased.length === 0 ? (
            <div className="changes-empty">No decreases detected</div>
          ) : (
            decreased.map((row) => (
              <ChangeRow key={row.service} row={row} direction="down" />
            ))
          )}
        </div>
        {newServices.length > 0 && (
          <div>
            <div className="changes-section-label">New services</div>
            {newServices.map((row) => (
              <ChangeRow key={row.service} row={row} direction="up" />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
