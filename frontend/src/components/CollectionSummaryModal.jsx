import { useEffect } from 'react'

import {
  formatDate,
  formatDateTime,
  formatMoneyOrDash,
} from '../utils/format'

import CostDriverList from './dashboard/CostDriverList'

export default function CollectionSummaryModal({
  open,
  loading,
  error,
  summary,
  onClose,
}) {
  useEffect(() => {
    if (!open) return undefined

    function handleKeyDown(event) {
      if (event.key === 'Escape') onClose?.()
    }

    document.addEventListener('keydown', handleKeyDown)

    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = previousOverflow
    }
  }, [open, onClose])

  if (!open) return null

  const scan = summary?.scan
  const costCollection = summary?.cost_collection
  const plan = Array.isArray(summary?.collection_plan)
    ? summary.collection_plan
    : []

  return (
    <div
      className="overlay open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="collection-summary-title"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose?.()
      }}
    >
      <div className="modal modal-large">
        <div className="modal-head">
          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            aria-label="Close collection summary"
          >
            ×
          </button>

          <div className="modal-eyebrow">
            <span className="modal-context-label">
              / Collection Summary
            </span>
          </div>

          <div className="modal-title-row">
            <h2
              id="collection-summary-title"
              className="modal-title"
            >
              Scan #{scan?.id ?? '—'} Summary
            </h2>
          </div>

          {scan && (
            <div className="modal-meta">
              <span>Account {scan.account_id || '—'}</span>
              <span>
                {formatDate(scan.start_date)} → {formatDate(scan.end_date)}
              </span>
              <span>{scan.region || 'All regions'}</span>
              <span>
                Threshold {formatMoneyOrDash(scan.cost_threshold)}
              </span>
              <span>Started {formatDateTime(scan.created_at)}</span>
            </div>
          )}
        </div>

        <div className="modal-body">
          {loading && (
            <div className="chart-empty">
              Loading collection summary…
            </div>
          )}

          {error && (
            <div className="page-error">{error}</div>
          )}

          {!loading && !error && summary && (
            <>
              <div className="detail-section">
                <div className="detail-section-head">
                  <h3 className="detail-section-title">
                    Cost Collection
                  </h3>
                </div>

                {costCollection ? (
                  <div className="detail-summary-grid">
                    <div className="detail-summary-card">
                      <span className="block-label">Collected total</span>
                      <strong className="mono">
                        {formatMoneyOrDash(costCollection.collected_total)}
                      </strong>
                    </div>

                    <div className="detail-summary-card">
                      <span className="block-label">Monthly total</span>
                      <strong className="mono">
                        {formatMoneyOrDash(costCollection.monthly_total)}
                      </strong>
                    </div>

                    <div className="detail-summary-card">
                      <span className="block-label">Difference</span>
                      <strong className="mono">
                        {formatMoneyOrDash(costCollection.difference)}
                      </strong>
                    </div>

                    <div className="detail-summary-card">
                      <span className="block-label">Match</span>
                      <strong>
                        <span
                          className={`sev-badge ${
                            costCollection.matches ? 'sev-low' : 'sev-high'
                          }`}
                        >
                          {costCollection.matches ? 'Match' : 'Mismatch'}
                        </span>
                      </strong>
                    </div>
                  </div>
                ) : (
                  <div className="diag-reason">
                    Reconciliation is not available for this scan
                    (it ran before collection-summary tracking was added).
                  </div>
                )}
              </div>

              <div className="detail-section">
                <div className="detail-section-head">
                  <h3 className="detail-section-title">
                    Cost Drivers
                  </h3>
                  <p className="detail-section-description">
                    Ranked service spend with usage-type breakdown
                    for the scanned period.
                  </p>
                </div>

                <CostDriverList drivers={summary.cost_analysis} />
              </div>

              <div className="detail-section">
                <div className="detail-section-head">
                  <h3 className="detail-section-title">
                    Collection Plan
                  </h3>
                  <p className="detail-section-description">
                    Resources targeted for collection, ranked by cost
                    context and priority.
                  </p>
                </div>

                {!plan.length ? (
                  <div className="chart-empty">
                    No collection plan was recorded for this scan.
                  </div>
                ) : (
                  <div className="detail-table-wrap">
                    <table className="detail-table">
                      <thead>
                        <tr>
                          <th>Resource type</th>
                          <th>Region</th>
                          <th>Cost</th>
                          <th>Priority</th>
                          <th>Service / usage type</th>
                          <th>Collector</th>
                        </tr>
                      </thead>
                      <tbody>
                        {plan.map((row, index) => (
                          <tr key={`${row.resource_type}-${index}`}>
                            <td>{row.resource_type}</td>
                            <td>{row.region}</td>
                            <td className="mono">
                              {formatMoneyOrDash(row.cost_context)}
                            </td>
                            <td>
                              <span
                                className={`sev-badge ${
                                  row.priority === 'high'
                                    ? 'sev-high'
                                    : row.priority === 'medium'
                                      ? 'sev-medium'
                                      : 'sev-low'
                                }`}
                              >
                                {row.priority}
                              </span>
                            </td>
                            <td>
                              {row.service} / {row.usage_type}
                            </td>
                            <td className="mono">{row.collector_name}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn btn-outline" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
