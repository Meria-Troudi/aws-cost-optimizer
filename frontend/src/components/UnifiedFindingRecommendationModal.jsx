import { sevClass, sevLabel, statusLabel, truncateId } from '../utils/format'

function normalizeDatapoints(datapoints = []) {
  const values = datapoints.map(Number).filter(Number.isFinite)
  if (!values.length) return []
  const max = Math.max(...values)
  if (max <= 0) return values.map(() => 3)
  return values.map((value) => Math.max(3, (value / max) * 24))
}

function Metric({ metric }) {
  const heights = normalizeDatapoints(metric.datapoints)

  return (
    <div className="metric-block">
      <div className="metric-head">
        <span className="metric-name">{metric.name}</span>
        <span className="metric-val">{metric.value}</span>
      </div>
      {heights.length > 0 ? (
        <div className="spark" aria-label={`${metric.name} metric trend`}>
          {heights.map((height, index) => (
            <span key={index} style={{ height: `${height}px` }} />
          ))}
        </div>
      ) : (
        <div className="metric-no-chart">No datapoints available</div>
      )}
    </div>
  )
}

export default function UnifiedFindingRecommendationModal({
  finding,
  recommendation,
  relatedFinding,
  onClose,
  onViewFinding,
}) {
  if (!finding && !recommendation) return null

  const showFinding = Boolean(finding)
  const showRecommendation = Boolean(recommendation)
  const resources = finding?.resourceIds?.length
    ? finding.resourceIds
    : finding?.resource
      ? [finding.resource]
      : []

  return (
    <div
      className="overlay open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="finding-modal-title"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="modal">
        <div className="modal-head">
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>

          <div className="modal-eyebrow">
            {showFinding && (
              <>
                <span className={`sev-badge ${sevClass(finding.severity)}`}>
                  {sevLabel(finding.severity)}
                </span>
                <span>{finding.confidence || 'Unknown'} confidence</span>
              </>
            )}
            {showRecommendation && !showFinding && (
              <>
                <span className={`sev-badge ${sevClass(recommendation.priority)}`}>
                  {sevLabel(recommendation.priority)}
                </span>
                <span>Recommended Action</span>
              </>
            )}
          </div>

          <div className="modal-title-row">
            <div>
              <div className="modal-title" id="finding-modal-title">
                {finding?.fullTitle || finding?.title || recommendation?.title}
              </div>
              <div className="modal-meta">
                {showFinding && (
                  <>
                    <span>
                      {finding.resourceCount || 0} affected resource
                      {finding.resourceCount === 1 ? '' : 's'}
                    </span>
                    <span>
                      Region <span className="mono">{finding.region || 'All regions'}</span>
                    </span>
                  </>
                )}
                {showRecommendation && !showFinding && (
                  <>
                    <span>{recommendation.meta}</span>
                    <span>{statusLabel(recommendation.status)}</span>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="modal-body">
          {showFinding && (
            <>
              <div className="block-label">Why this was flagged</div>
              <div className="diag-reason">{finding.reason || 'No explanation available.'}</div>

              {finding.evidenceItems?.length > 0 && (
                <>
                  <div className="block-label">Evidence</div>
                  {finding.evidenceItems.map((item, i) => (
                    <div className="cond-item" key={i}>
                      <span className="cond-check">{item.supports_finding ? '✓' : '○'}</span>
                      <div>
                        <div className="name">{item.label}</div>
                        <div className="actual">{item.observed}</div>
                        {item.description && <div className="cond-desc">{item.description}</div>}
                      </div>
                    </div>
                  ))}
                </>
              )}

              {finding.limitations?.length > 0 && (
                <>
                  <div className="block-label">Limitations</div>
                  <ul className="limit-list">
                    {finding.limitations.map((item, i) => (
                      <li key={i}>{item}</li>
                    ))}
                  </ul>
                </>
              )}

              {resources.length > 0 && (
                <>
                  <div className="block-label">Affected resources · {resources.length}</div>
                  <div className="resource-id-list">
                    {resources.map((rid) => (
                      <div className="resource-id-row mono" key={rid}>
                        {truncateId(rid, 24)}
                      </div>
                    ))}
                  </div>
                </>
              )}

              {finding.metrics?.length > 0 && (
                <>
                  <div className="block-label">Metrics</div>
                  {finding.metrics.map((m, i) => (
                    <Metric key={i} metric={m} />
                  ))}
                </>
              )}

              {finding.costCards?.length > 0 && (
                <>
                  <div className="block-label">Cost context</div>
                  <div className="cost-grid">
                    {finding.costCards.map((c, i) => (
                      <div className="cost-card" key={i}>
                        <div className="k">{c.k}</div>
                        <div className="v">{c.v}</div>
                      </div>
                    ))}
                  </div>
                </>
              )}

            </>
          )}

          {showRecommendation && (
            <>
              {showFinding && (
                <div style={{ marginTop: 24, borderTop: '1px solid var(--line)', paddingTop: 20 }}>
                  <div className="block-label">Recommended action</div>
                  <div className="diag-reason">{recommendation.action}</div>
                </div>
              )}

              {!showFinding && (
                <>
                  <div className="block-label">Recommended action</div>
                  <div className="diag-reason">{recommendation.action || 'No action provided.'}</div>
                </>
              )}

              {recommendation.rationale && (
                <>
                  <div className="block-label">Why this is recommended</div>
                  <div className="diag-reason">{recommendation.rationale}</div>
                </>
              )}

              <div className="block-label">Expected impact</div>
              <div className="cost-grid">
                <div className="cost-card">
                  <div className="k">Confidence</div>
                  <div className="v">{recommendation.confidence || '—'}</div>
                </div>
              </div>

              <div className="block-label">Status</div>
              <div className="status-pending">{statusLabel(recommendation.status)}</div>

              <div className="block-label">Related finding</div>
              {relatedFinding ? (
                <div className="diag-reason">
                  {relatedFinding.fullTitle || relatedFinding.title}
                </div>
              ) : (
                <div className="warn-box">
                  <span>⚠️</span>
                  <span>Related finding is unavailable.</span>
                </div>
              )}
            </>
          )}
        </div>

        <div className="modal-foot">
          <button type="button" className="btn btn-outline" onClick={onClose}>
            Close
          </button>
          {showFinding && onViewFinding && (
            <button type="button" className="btn btn-primary" onClick={() => onViewFinding(finding)}>
              View Full Finding
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
