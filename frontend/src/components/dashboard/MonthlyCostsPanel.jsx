import { useEffect, useState } from 'react'

import { getMonthlyDimension } from '../../api/client'

import MonthlyCostBreakdownChart from './MonthlyCostBreakdownChart'

function withSharePct(monthlyServiceCost) {
  return (Array.isArray(monthlyServiceCost) ? monthlyServiceCost : []).map(
    (row) => {
      const items = Array.isArray(row.services) ? row.services : []
      const total = items.reduce((sum, item) => sum + (item.amount ?? 0), 0)

      return {
        month: row.month,
        items: items.map((item) => ({
          key: item.service,
          amount: item.amount,
          share_pct: total ? (item.amount / total) * 100 : 0,
        })),
      }
    },
  )
}

export default function MonthlyCostsPanel({ monthlyServiceCost }) {
  const [operationData, setOperationData] = useState(null)
  const [operationLoading, setOperationLoading] = useState(true)
  const [operationError, setOperationError] = useState(null)

  useEffect(() => {
    let active = true

    getMonthlyDimension({ dimension: 'OPERATION', history_months: 6 })
      .then((response) => {
        if (!active) return
        setOperationData(response)
      })
      .catch((err) => {
        if (!active) return
        setOperationError(
          err.message || 'Unable to load monthly cost by operation.',
        )
      })
      .finally(() => {
        if (!active) return
        setOperationLoading(false)
      })

    return () => {
      active = false
    }
  }, [])

  // Side-by-side 3-column layout has less room per chart than a
  // full-width one did -- cap to the most recent months so each
  // chart fits without needing its own horizontal scrollbar.
  const VISIBLE_MONTHS = 4

  const serviceMonthly = withSharePct(monthlyServiceCost).slice(
    -VISIBLE_MONTHS,
  )

  const operationMonthly = (
    Array.isArray(operationData?.monthly) ? operationData.monthly : []
  ).slice(-VISIBLE_MONTHS)

  return (
    <section className="panel monthly-costs-panel section-gap">
      <div className="panel-head">
        <div>
          <div className="eyebrow">/ Monthly Costs</div>

          <h2 className="panel-title">Monthly cost breakdown</h2>

          <p className="panel-sub">
            Compare spend across months by service, operation or product.
          </p>
        </div>
      </div>

      <div className="monthly-costs-columns">
        <div className="monthly-costs-column">
          <h4>Service</h4>
          <MonthlyCostBreakdownChart
            monthly={serviceMonthly}
            emptyMessage="No monthly cost data is available yet."
          />
        </div>

        <div className="monthly-costs-column">
          <h4>Operation</h4>
          {operationError ? (
            <div className="page-error">{operationError}</div>
          ) : operationLoading && !operationData ? (
            <div className="chart-empty">
              <span className="chart-empty-icon">&#9633;</span>
              <strong>Loading&hellip;</strong>
            </div>
          ) : (
            <MonthlyCostBreakdownChart
              monthly={operationMonthly}
              emptyMessage="No monthly cost-by-operation data is available yet."
            />
          )}
        </div>

        <div className="monthly-costs-column">
          <h4>Product</h4>
          <MonthlyCostBreakdownChart
            monthly={serviceMonthly}
            emptyMessage="No monthly cost data is available yet."
          />
        </div>
      </div>
    </section>
  )
}
