import { useEffect, useState } from 'react'

import { getScans } from '../api/client'
import { formatDate, formatDateTime, pluralize } from '../utils/format'
import { isDoneStatus, isFailedStatus, isRunningStatus } from '../utils/scanStatus'

function statusLabel(status) {
  if (isRunningStatus(status)) return 'Running'
  if (isFailedStatus(status)) return 'Failed'
  if (isDoneStatus(status)) return 'Completed'
  return status || 'Unknown'
}

function statusTone(status) {
  if (isRunningStatus(status)) return 'running'
  if (isFailedStatus(status)) return 'failed'
  if (isDoneStatus(status)) return 'done'
  return ''
}

export default function AnalysisHistoryPage({ onViewResults, onRunAnalysis, onBack }) {
  const [scans, setScans] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true

    getScans()
      .then((response) => {
        if (!active) return
        setScans(Array.isArray(response) ? response : [])
      })
      .catch((err) => {
        if (!active) return
        setError(err.message || 'Unable to load analysis history.')
      })

    return () => {
      active = false
    }
  }, [])

  const rows = (scans || [])
    .slice()
    .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))

  return (
    <div className="history-page">
      <div className="header-row">
        <div className="headline">
          <div className="eyebrow">/ Analysis History</div>
          <h1>Previous scans and results</h1>
          <div className="sub">What did previous analyses find?</div>
        </div>

        <div className="dashboard-actions">
          <button type="button" className="small-btn" onClick={onBack}>
            ← Back to overview
          </button>

          <button type="button" className="small-btn primary-btn" onClick={onRunAnalysis}>
            Run New Analysis
          </button>
        </div>
      </div>

      {error ? (
        <div className="page-error section-gap">{error}</div>
      ) : !scans ? (
        <div className="chart-empty">
          <span className="chart-empty-icon">&#8644;</span>
          <strong>Loading&hellip;</strong>
        </div>
      ) : rows.length === 0 ? (
        <div className="chart-empty">
          <span className="chart-empty-icon">&#8644;</span>
          <strong>No scans have been run yet.</strong>
        </div>
      ) : (
        <div className="history-table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Period</th>
                <th>Region</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Recommendations</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {rows.map((scan) => (
                <tr
                  key={scan.id}
                  className="history-row"
                  onClick={() => onViewResults(scan.id)}
                  title={formatDateTime(scan.created_at)}
                >
                  <td>{formatDate(scan.created_at)}</td>
                  <td>
                    {formatDate(scan.start_date)} → {formatDate(scan.end_date)}
                  </td>
                  <td>{scan.region || 'All regions'}</td>
                  <td>
                    <span className={`history-status ${statusTone(scan.status)}`}>
                      {statusLabel(scan.status)}
                    </span>
                  </td>
                  <td>{scan.findings_count ?? '—'}</td>
                  <td>{scan.recommendations_count ?? '—'}</td>
                  <td className="history-row-action">View details →</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
