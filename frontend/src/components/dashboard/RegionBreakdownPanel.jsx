import {
  formatMoneyOrDash,
  formatPct,
} from '../../utils/format'

export default function RegionBreakdownPanel({
  regionCosts,
}) {
  const rows = Array.isArray(regionCosts)
    ? regionCosts
        .slice()
        .sort(
          (a, b) =>
            Number(
              b.cost ??
                b.current_cost ??
                b.amount ??
                0,
            ) -
            Number(
              a.cost ??
                a.current_cost ??
                a.amount ??
                0,
            ),
        )
        .slice(0, 6)
    : []

  const maxCost = Math.max(
    ...rows.map(row =>
      Number(
        row.cost ??
          row.current_cost ??
          row.amount ??
          0,
      ),
    ),
    1,
  )

  const totalCost = rows.reduce(
    (sum, row) =>
      sum +
      Number(
        row.cost ??
          row.current_cost ??
          row.amount ??
          0,
      ),
    0,
  )

  return (
    <section className="snapshot-panel region-concentration-panel">

      <div className="snapshot-panel-head">

        <div>
          <div className="eyebrow">
            / Regional Distribution
          </div>

          <h3>
            Where AWS workloads are billed
          </h3>

          <p>
            Regional concentration and
            current cost exposure.
          </p>
        </div>

        <span className="snapshot-count">
          {rows.length} regions
        </span>

      </div>

      {!rows.length ? (
        <div className="snapshot-empty">
          <span>◎</span>
          No regional cost data is available yet.
        </div>
      ) : (
        <>
          <div className="region-summary-card">
            <span>Total regional spend</span>
            <strong className="mono">
              {formatMoneyOrDash(totalCost)}
            </strong>
          </div>

          <div className="region-concentration-list">

            {rows.map((row, index) => {
              const name =
                row.region ||
                row.name ||
                'Unknown region'

              const cost =
                Number(
                  row.cost ??
                    row.current_cost ??
                    row.amount ??
                    0,
                )

              const share =
                row.share_pct != null
                  ? Number(
                      row.share_pct,
                    )
                  : totalCost > 0
                    ? (cost / totalCost) *
                      100
                    : 0

              const width =
                (cost / maxCost) * 100

              return (
                <div
                  className={`region-concentration-row ${
                    index === 0
                      ? 'featured'
                      : ''
                  }`}
                  key={name}
                >

                  <div className="region-concentration-top">

                    <div className="region-name-wrap">

                      <span className="region-rank mono">
                        {String(
                          index + 1,
                        ).padStart(
                          2,
                          '0',
                        )}
                      </span>

                      <div className="region-marker">
                        ◈
                      </div>

                      <div>
                        <strong>
                          {name}
                        </strong>

                        <span>
                          {share.toFixed(1)}%
                          {' '}of regional spend
                        </span>
                      </div>

                    </div>

                    <div className="region-value">
                      <strong className="mono">
                        {formatMoneyOrDash(
                          cost,
                        )}
                      </strong>

                      {row.change_pct != null && (
                        <span
                          className={
                            Number(
                              row.change_pct,
                            ) >= 0
                              ? 'up'
                              : 'down'
                          }
                        >
                          {formatPct(
                            row.change_pct,
                            true,
                          )}
                        </span>
                      )}
                    </div>

                  </div>

                  <div className="region-bar-track">

                    <div
                      className="region-bar-fill"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            0,
                            width,
                          ),
                        )}%`,
                      }}
                    />

                  </div>

                </div>
              )
            })}

          </div>
        </>
      )}

    </section>
  )
}