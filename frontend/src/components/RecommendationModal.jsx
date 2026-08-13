import { sevLabel, truncateId } from '../utils/format'

function sevClass(s) {
  if (s === 'high') return 'sev-high'
  if (s === 'medium') return 'sev-medium'
  return 'sev-low'
}

function statusLabel(status) {
  if (!status) return 'Pending review'
  return status.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export default function RecommendationModal({
  recommendation,
  relatedFinding,
  onClose,
  onViewFinding,
}) {
  if (!recommendation) return null

  const priority = (recommendation.priority || 'medium').toLowerCase()
  const affectedResources =
    recommendation.affectedResources ||
    recommendation.affected_resources ||
    relatedFinding?.resourceIds ||
    []
  const affectedCount =
    recommendation.affectedResourceCount ||
    recommendation.affected_resource_count ||
    affectedResources.length

  return (
    <div
      className={`overlay ${recommendation ? 'open' : ''}`}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="modal">
        <div className="modal-head">
          <button type="button" className="modal-close" onClick={onClose}>
            ✕
          </button>
          <div className="modal-eyebrow">
            <span className={`sev-badge ${sevClass(priority)}`}>
              {sevLabel(priority)}
            </span>
            <span>{recommendation.confidence || 'medium'} confidence</span>
          </div>
          <div className="modal-title-row">
            <div className="modal-ico" style={{ background: 'var(--slate)' }}>
              →
            </div>
            <div>
              <div className="modal-title">{recommendation.title}</div>
              <div className="modal-meta">
                <span>
                  {affectedCount} affected resource{affectedCount === 1 ? '' : 's'}
                </span>
                <span>{statusLabel(recommendation.status)}</span>
                {recommendation.resource_type && (
                  <span>
                    Type <span className="mono">{recommendation.resource_type}</span>
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="modal-body">
          <div className="block-label">Why this is recommended</div>
          <div className="diag-reason">
            {recommendation.reason ||
              recommendation.rationale ||
              recommendation.explanation ||
              relatedFinding?.reason ||
              'No rationale provided.'}
          </div>

          <div className="block-label">Recommended action</div>
          <div className="diag-reason">{recommendation.action}</div>

          {affectedResources.length > 0 && (
            <>
              <div className="block-label">
                Affected resource IDs · {affectedCount}
              </div>
              <div className="resource-id-list">
                {affectedResources.map((rid) => (
                  <div className="resource-id-row mono" key={rid}>
                    {truncateId(rid, 32)}
                  </div>
                ))}
              </div>
            </>
          )}

          <div className="block-label">Expected impact</div>
          <div className="cost-grid">
            <div className="cost-card">
              <div className="k">Confidence</div>
              <div className="v">{recommendation.confidence || '—'}</div>
            </div>
           </div>

          {relatedFinding ? (
            <>
              <div className="block-label">Related finding</div>
              <div className="diag-reason">{relatedFinding.fullTitle || relatedFinding.title}</div>
              {relatedFinding.reason && relatedFinding.reason !== recommendation.reason && (
                <div className="cond-desc">{relatedFinding.reason}</div>
              )}
            </>
          ) : (
            recommendation.finding_id == null && (
              <div className="warn-box">
                <span>⚠️</span>
                <span>Related finding unavailable for this recommendation.</span>
              </div>
            )
          )}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn btn-outline" onClick={onClose}>
            Close
          </button>
          {relatedFinding && (
            <button type="button" className="btn btn-primary" onClick={onViewFinding}>
              View Finding
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
