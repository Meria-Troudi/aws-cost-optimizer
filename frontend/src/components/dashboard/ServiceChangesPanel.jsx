import {
  formatChange,
  formatMoneyOrDash,
  formatPct,
} from '../../utils/format'

function ChangeRow({
  row,
  direction,
  rank,
}) {
  const service =
    row.service_short ||
    row.service ||
    row.name ||
    'AWS service'

  const amount =
    row.change_amount ??
    row.difference

  const pct =
    row.change_pct ??
    row.percentage_change

  const current =
    row.cost ??
    row.current_amount ??
    row.current_cost

  const isUp = direction === 'up'

  return (
    <div
      className={`movement-row ${direction}`}
    >
      <span className="movement-rank mono">
        {String(rank).padStart(2, '0')}
      </span>

      <div className="movement-icon">
        {isUp ? '↗' : '↘'}
      </div>

      <div className="movement-content">

        <div className="movement-title">
          {service}
        </div>

        <div className="movement-meta">
          {formatMoneyOrDash(current)}
          {' '}current spend
        </div>

      </div>

      <span className={`movement-delta mono ${direction}`}>
        {isUp ? '▲' : '▼'}{' '}
        {amount != null
          ? formatChange(amount)
          : '—'}

        {pct != null && (
          <small>
            {formatPct(pct, true)}
          </small>
        )}
      </span>
    </div>
  )
}

function MovementColumn({
  title,
  subtitle,
  rows,
  direction,
}) {
  const total = rows.reduce(
    (sum, row) =>
      sum +
      Math.abs(
        Number(
          row.change_amount ??
            row.difference ??
            0,
        ),
      ),
    0,
  )

  return (
    <div
      className={`movement-column ${direction}`}
    >

      <div className="movement-column-head">

        <div className="movement-column-icon">
          {direction === 'up'
            ? '↑'
            : '↓'}
        </div>

        <div>
          <strong>{title}</strong>
          <span>{subtitle}</span>
        </div>

        <div className="movement-total mono">
          {formatMoneyOrDash(total)}
        </div>

      </div>

      {!rows.length ? (
        <div className="movement-empty">
          <span>✓</span>
          No material movements
        </div>
      ) : (
        rows.map((row, index) => (
          <ChangeRow
            key={
              row.service ||
              row.service_short ||
              row.name ||
              index
            }
            row={row}
            direction={direction}
            rank={index + 1}
          />
        ))
      )}

    </div>
  )
}

export default function ServiceChangesPanel({
  serviceChanges,
}) {
  const increased =
    Array.isArray(
      serviceChanges?.increased,
    )
      ? serviceChanges.increased.slice(
          0,
          5,
        )
      : []

  const decreased =
    Array.isArray(
      serviceChanges?.decreased,
    )
      ? serviceChanges.decreased.slice(
          0,
          5,
        )
      : []

  return (
    <section className="snapshot-panel movement-panel">

      <div className="snapshot-panel-head">

        <div>
          <div className="eyebrow">
            / Cost Movements
          </div>

          <h3>
            What changed in AWS spend
          </h3>
        </div>

        <span className="snapshot-count">
          {increased.length +
            decreased.length}{' '}
          movements
        </span>

      </div>

      <div className="movement-grid">

        <MovementColumn
          title="Largest increases"
          subtitle="Services adding cost"
          rows={increased}
          direction="up"
        />

        <MovementColumn
          title="Largest decreases"
          subtitle="Services reducing cost"
          rows={decreased}
          direction="down"
        />

      </div>

    </section>
  )
}