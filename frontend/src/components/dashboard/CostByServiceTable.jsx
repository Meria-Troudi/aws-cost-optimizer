import {
  formatChange,
  formatMoneyOrDash,
  formatPct,
} from '../../utils/format'

function getChange(row) {
  return (
    row.change_amount ??
    row.difference ??
    null
  )
}

function getPct(row) {
  return (
    row.change_pct ??
    row.percentage_change ??
    null
  )
}

function getCost(row) {
  return Number(
    row.current_cost ??
      row.amount ??
      row.current_amount ??
      row.cost ??
      0,
  )
}

function ServiceRow({
  row,
  index,
  maxCost,
  totalCost,
}) {
  const service =
    row.service_short ||
    row.service ||
    row.name ||
    'AWS service'

  const cost = getCost(row)
  const change = getChange(row)
  const pct = getPct(row)

  const share =
    row.share_pct != null
      ? Number(row.share_pct)
      : totalCost > 0
        ? (cost / totalCost) * 100
        : 0

  const width =
    maxCost > 0
      ? (cost / maxCost) * 100
      : 0

  const direction =
    change == null
      ? 'neutral'
      : Number(change) >= 0
        ? 'up'
        : 'down'

  const initials =
    service
      .split(/\s+/)
      .slice(0, 2)
      .map(part => part[0])
      .join('')
      .toUpperCase()

  return (
    <div
      className={`service-concentration-row ${
        index === 0
          ? 'featured'
          : ''
      }`}
    >
      <div className="service-concentration-top">

        <div className="service-name-wrap">

          <span className="service-rank mono">
            {String(index + 1).padStart(
              2,
              '0',
            )}
          </span>

          <span className="service-avatar">
            {initials}
          </span>

          <div>
            <strong>
              {service}
            </strong>

            <span className="service-meta">
              {share.toFixed(1)}% of total spend
            </span>
          </div>

        </div>

        <div className="service-value">

          <strong className="mono">
            {formatMoneyOrDash(cost)}
          </strong>

          {pct != null && (
            <span className={direction}>
              {formatPct(
                pct,
                true,
              )}
            </span>
          )}

        </div>

      </div>

      <div className="service-bar-track">

        <div
          className={`service-bar-fill ${
            index === 0
              ? 'featured'
              : ''
          }`}
          style={{
            width: `${Math.min(
              100,
              Math.max(0, width),
            )}%`,
          }}
        />

      </div>

      <div className="service-row-footer">

        <span>
          Spend concentration
        </span>

        {change != null && (
          <span
            className={`service-change ${direction}`}
          >
            {formatChange(change)}
          </span>
        )}

      </div>
    </div>
  )
}

export default function CostByServiceTable({
  services,
  limit = 8,
}) {
  const rows = Array.isArray(services)
    ? services
        .slice()
        .sort(
          (a, b) =>
            getCost(b) -
            getCost(a),
        )
        .slice(0, limit)
    : []

  const maxCost = Math.max(
    ...rows.map(getCost),
    1,
  )

  const totalCost = rows.reduce(
    (sum, row) =>
      sum + getCost(row),
    0,
  )

  if (!rows.length) {
    return (
      <section className="snapshot-panel service-concentration-panel">

        <div className="snapshot-panel-head">
          <div>
            <div className="eyebrow">
              / Service Concentration
            </div>

            <h3>
              Where AWS spend is concentrated
            </h3>

            <p>
              Ranked service contribution
              for the selected period.
            </p>
          </div>
        </div>

        <div className="snapshot-empty">
          <span>◌</span>
          No service cost data is available yet.
        </div>

      </section>
    )
  }

  return (
    <section className="snapshot-panel service-concentration-panel">

      <div className="snapshot-panel-head">

        <div>
          <div className="eyebrow">
            / Service Concentration
          </div>

          <h3>
            Where AWS spend is concentrated
          </h3>

          <p>
            Ranked contribution with cost
            movement and concentration.
          </p>
        </div>

        <span className="snapshot-count">
          {rows.length} services
        </span>

      </div>

      <div className="service-summary-strip">
        <div>
          <span>Tracked spend</span>
          <strong className="mono">
            {formatMoneyOrDash(totalCost)}
          </strong>
        </div>

        <div>
          <span>Top service</span>
          <strong>
            {rows[0]
              ?.service_short ||
              rows[0]
                ?.service ||
              rows[0]?.name ||
              '—'}
          </strong>
        </div>
      </div>

      <div className="service-concentration-list">
        {rows.map((row, index) => (
          <ServiceRow
            key={
              row.service ||
              row.service_short ||
              row.name ||
              index
            }
            row={row}
            index={index}
            maxCost={maxCost}
            totalCost={totalCost}
          />
        ))}
      </div>

    </section>
  )
}