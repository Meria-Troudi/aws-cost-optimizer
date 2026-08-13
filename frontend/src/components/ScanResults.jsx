import FindingsTable from './FindingsTable'
import { countBySeverity } from '../data/findings'

function sevClass(s) {
  if (s === 'high') return 'sev-high'
  if (s === 'medium') return 'sev-medium'
  return 'sev-low'
}

export default function ScanResults({
  scanData,
  findings,
  recommendations,
  loading,
  error,
  hasResults,
  latestAttempt,
  onFindingClick,
  onRecommendationClick,
  onBackToDashboard,
}) {
  const counts = countBySeverity(findings)
  const totalFindings = Object.keys(findings).length
  const showFailedBanner =
    latestAttempt?.status === 'failed' && hasResults

  const regionLabel = scanData?.region || 'All regions'
  const presentedRecs = recommendations || []
  const pendingReview = presentedRecs.filter(
    (r) => !r.status || r.status === 'new' || r.status === 'pending_review',
  ).length

  return (
    <>
      <div className="dashboard-head">
        <div className="headline">
          <h1>
            Analysis Results
            <br />
          </h1>
          <div className="sub">
            {hasResults ? (
              <>
                Analysis #{scanData.scan_id} · {scanData.start_date} → {scanData.end_date} ·{' '}
                {regionLabel}
              </>
            ) : (
              'Results appear here after a completed cost analysis.'
            )}
          </div>
        </div>
        <button type="button" className="small-btn" onClick={onBackToDashboard}>
          ← Back to Overview
        </button>
      </div>

      {loading && <div className="page-loading">Loading analysis results…</div>}
      {error && <div className="page-error">{error}</div>}

      {showFailedBanner && (
        <div className="page-warn">
          Latest analysis #{latestAttempt.scan_id} failed. Showing results from analysis #
          {scanData.scan_id}.
        </div>
      )}

      {!loading && !hasResults && (
        <div className="empty-state section-gap">
          <div className="empty-ico">◎</div>
          <h3>No analysis results</h3>
          <p>Start a cost analysis from Overview or the Analysis tab.</p>
        </div>
      )}

      {!loading && hasResults && (
        <>
          <div className="dashboard-kpis">
            <div className="dash-kpi primary">
              <div className="label">Detected Findings</div>
              <div className="value">{totalFindings}</div>
              <div className="meta">
                {counts.high} high · {counts.medium} medium · {counts.low} low
              </div>
            </div>
            <div className="dash-kpi">
              <div className="label">Recommended Actions</div>
              <div className="value">{presentedRecs.length}</div>
              <div className="meta">
                {pendingReview > 0
                  ? `${pendingReview} pending review`
                  : 'Actions for review'}
              </div>
            </div>
          </div>

          <div className="dash-section">
            <div className="section-label">Detected Findings</div>
            <p className="tab-note">
              Conditions detected during the analysis. Review the evidence before considering an
              action.
            </p>
            {totalFindings === 0 ? (
              <div className="empty-state">
                <div className="empty-ico">▤</div>
                <h3>No findings</h3>
                <p>This analysis did not produce any detected findings.</p>
              </div>
            ) : (
              <FindingsTable findings={findings} onRowClick={onFindingClick} />
            )}
          </div>

          {presentedRecs.length > 0 && (
            <div className="dash-section">
              <div className="panel">
                <div className="panel-head">
                  <div>
                    <div className="panel-title">Recommended Actions</div>
                    <div className="panel-sub">
                      Actions proposed from detected findings. Review before implementation.
                    </div>
                  </div>
                </div>
                {presentedRecs.map((rec) => (
                  <div className="rec-row" key={rec.id}>
                    <span className={`sev-badge ${sevClass(rec.priority)}`}>
                      {rec.priorityLabel}
                    </span>
                    <div className="rec-info">
                      <div className="rec-title">{rec.title}</div>
                      <div className="rec-meta">
                        {rec.affectedResourceCount || 0} affected · {rec.confidence} confidence ·{' '}
                      </div>
                      {rec.reason && (
                        <div className="rec-reason">{rec.reason}</div>
                      )}
                    </div>
                    <button
                      type="button"
                      className="btn-view-more"
                      onClick={() => onRecommendationClick?.(rec)}
                    >
                      View Recommendation
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </>
  )
}
