import { useEffect, useState } from 'react'

import { getScans } from '../../api/client'
import { formatDate, pluralize } from '../../utils/format'
import { isDoneStatus, isFailedStatus, isRunningStatus } from '../../utils/scanStatus'

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

export default function RecentScansPanel({ onViewResults, onViewHistory }) {
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
        setError(err.message || 'Unable to load past scans.')
      })

    return () => {
      active = false
    }
  }, [])

  const recent = (scans || [])
    .slice()
    .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))
    .slice(0, 3)

  if (error) return null
  if (scans && recent.length === 0) return null

  return (
    <div className="recent-scans">
      <div className="recent-scans-head">
        <span className="recent-scans-title">Recent scans</span>

        <button
          type="button"
          className="recent-scans-see-all"
          onClick={onViewHistory}
        >
          See all →
        </button>
      </div>

      {!scans ? (
        <div className="recent-scans-loading">Loading…</div>
      ) : (
        <div className="recent-scans-rows">
          {recent.map((scan) => (
            <button
              type="button"
              key={scan.id}
              className="recent-scan-row"
              onClick={() => onViewResults(scan.id)}
            >
              <span className={`recent-scan-status ${statusTone(scan.status)}`} />

              <span className="recent-scan-date">{formatDate(scan.created_at)}</span>

              <span className="recent-scan-region">{scan.region || 'All regions'}</span>

              <span className="recent-scan-summary">
                {isDoneStatus(scan.status)
                  ? `${pluralize(scan.findings_count ?? 0, 'finding')} · ${pluralize(scan.recommendations_count ?? 0, 'recommendation')}`
                  : statusLabel(scan.status)}
              </span>

              <span className="recent-scan-link">View details →</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
