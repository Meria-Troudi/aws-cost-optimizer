import { useEffect, useState } from 'react'
import { truncateId } from '../utils/format'

function sevClass(s) {
  if (s === 'high') return 'sev-high'
  if (s === 'medium') return 'sev-medium'
  return 'sev-low'
}

function formatPeriod(period) {
  if (!period) return null
  const start = period.start || period.start_date
  const end = period.end || period.end_date
  if (!start && !end) return null
  return `${start || '?'} → ${end || '?'}`
}

export default function FindingsModal({ finding, onClose }) {
  const [tab, setTab] = useState('overview')

  useEffect(() => {
    if (finding) setTab('overview')
  }, [finding])

  useEffect(() => {
    function onKey(e) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  if (!finding) return null

  // Defensive defaults: a finding may come from an older scan payload that
  // predates one of these fields. Every array read below is guarded so a
  // partial record shows an empty-state instead of throwing.
  const conditionGroups = finding.conditionGroups || []
  const evidenceItems = finding.evidenceItems || []
  const metrics = finding.metrics || []
  const limitations = finding.limitations || []
  const topo = finding.topo || []
  const costCards = finding.costCards || []
  const resourceIds = finding.resourceIds?.length ? finding.resourceIds : [finding.resource].filter(Boolean)

  const tabs = ['overview', 'conditions', 'evidence', 'resources', 'cost']
  const periodLabel = formatPeriod(finding.observationPeriod)

  return (
    <div
      className={`overlay ${finding ? 'open' : ''}`}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="modal">
        <div className="modal-head">
          <button type="button" className="modal-close" onClick={onClose}>
            ✕
          </button>
          <div className="modal-eyebrow">
            <span className={`sev-badge ${sevClass(finding.severity)}`}>{finding.sevLabel}</span>
            <span>{finding.confidence} confidence</span>
            {finding.category && <span>{finding.category}</span>}
          </div>
          <div className="modal-title-row">
            <div className="modal-ico" style={{ background: finding.iconBg }}>
              {finding.icon}
            </div>
            <div>
              <div className="modal-title">{finding.fullTitle}</div>
              <div className="modal-meta">
                <span>
                  {finding.resourceCount} affected resource{finding.resourceCount === 1 ? '' : 's'}
                </span>
                <span>
                  Region <span className="mono">{finding.region}</span>
                </span>
                {periodLabel && (
                  <span>
                    Period <span className="mono">{periodLabel}</span>
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="modal-tabs">
          {tabs.map((name) => (
            <div
              key={name}
              className={`modal-tab ${tab === name ? 'active' : ''}`}
              onClick={() => setTab(name)}
              role="tab"
            >
              {name.charAt(0).toUpperCase() + name.slice(1)}
            </div>
          ))}
        </div>

        <div className="modal-body">
          {tab === 'overview' && (
            <div className="modal-pane active">
              <div className="block-label">Why this was flagged</div>
              <div className="diag-reason">{finding.reason}</div>

              {finding.billingDetails && (
                <>
                  <div className="block-label">Billing mismatch</div>
                  <div className="topo-grid">
                    <div className="topo-item">
                      <div className="k">Billing class</div>
                      <div className="v mono">{finding.billingDetails.billing_class || '—'}</div>
                    </div>
                    <div className="topo-item">
                      <div className="k">Discovered class</div>
                      <div className="v mono">{finding.billingDetails.resource_class || '—'}</div>
                    </div>
                    <div className="topo-item">
                      <div className="k">Status</div>
                      <div className="v">{finding.billingDetails.status || 'mismatch'}</div>
                    </div>
                  </div>
                </>
              )}

              {finding.blocksOptimization && (
                <div className="warn-box">
                  <span>⚠️</span>
                  <span>
                    This finding blocks optimization recommendations until the underlying data
                    issue is resolved.
                  </span>
                </div>
              )}

              {limitations.length > 0 && (
                <>
                  <div className="block-label">Limitations</div>
                  <ul className="limit-list">
                    {limitations.map((item, i) => (
                      <li key={i}>{item}</li>
                    ))}
                  </ul>
                </>
              )}
              <div className="confidence-row">
                <span>Confidence</span>
                <span className="confidence-pill">{finding.confidence}</span>
              </div>
            </div>
          )}

          {tab === 'conditions' && (
            <div className="modal-pane active">
              <div className="block-label">Conditions</div>
              {conditionGroups.length === 0 ? (
                <div className="evidence-empty">
                  No per-resource conditions available for this finding.
                </div>
              ) : (
                conditionGroups.map((group) => (
                  <div className="condition-group" key={group.resourceId || 'global'}>
                    {group.resourceId && (
                      <div className="condition-resource mono">
                        Resource: {truncateId(group.resourceId, 32)}
                      </div>
                    )}
                    {(group.statements || []).map((stmt, i) => (
                      <div className="cond-item" key={`${group.resourceId}-${stmt.name}-${i}`}>
                        <span className={`cond-check ${stmt.statusClass || ''}`}>
                          {stmt.supportsFinding ? '✓' : '○'}
                        </span>
                        <div className="cond-body">
                          <div className="name">{stmt.label}</div>
                          <div className="cond-grid">
                            <div>
                              <span className="cond-k">Expected</span>
                              <span className="cond-v">{stmt.expected}</span>
                            </div>
                            <div>
                              <span className="cond-k">Actual</span>
                              <span className="cond-v">{stmt.actual}</span>
                            </div>
                            {stmt.status && (
                              <div>
                                <span className="cond-k">Status</span>
                                <span className={`cond-v ${stmt.statusClass || ''}`}>{stmt.status}</span>
                              </div>
                            )}
                          </div>
                          {stmt.description && <div className="cond-desc">{stmt.description}</div>}
                          {stmt.source?.length > 0 && (
                            <div className="cond-source mono">source: {stmt.source.join(', ')}</div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ))
              )}
            </div>
          )}

          {tab === 'evidence' && (
            <div className="modal-pane active">
              <div className="block-label">Evidence</div>
              {evidenceItems.length === 0 ? (
                <div className="evidence-empty">No structured evidence available for this finding.</div>
              ) : (
                evidenceItems.map((item, i) => (
                  <div className="cond-item" key={i}>
                    <span className="cond-check">{item.supports_finding ? '✓' : '○'}</span>
                    <div>
                      <div className="name">{item.label}</div>
                      <div className="cond-grid">
                        {item.expected != null && (
                          <div>
                            <span className="cond-k">Expected</span>
                            <span className="cond-v">{item.expected}</span>
                          </div>
                        )}
                        {item.actual != null && (
                          <div>
                            <span className="cond-k">Actual</span>
                            <span className="cond-v">{item.actual}</span>
                          </div>
                        )}
                        {item.status && (
                          <div>
                            <span className="cond-k">Status</span>
                            <span className="cond-v">{item.status}</span>
                          </div>
                        )}
                      </div>
                      {item.observed && <div className="actual">{item.observed}</div>}
                      {item.description && <div className="cond-desc">{item.description}</div>}
                      {item.source?.length > 0 && (
                        <div className="cond-source mono">source: {item.source.join(', ')}</div>
                      )}
                    </div>
                  </div>
                ))
              )}

              {metrics.length > 0 && (
                <>
                  <div className="block-label">Metrics</div>
                  {metrics.map((m, i) => (
                    <div className="metric-block" key={i}>
                      <div className="metric-head">
                        <span className="metric-name">{m.name}</span>
                        <span className="metric-val">{m.value}</span>
                      </div>
                      {m.status && (
                        <div className="metric-meta">
                          status={m.status}
                          {m.has_data != null && ` · has_data=${m.has_data}`}
                          {m.datapoints != null && ` · datapoints=${m.datapoints}`}
                        </div>
                      )}
                      {Array.isArray(m.datapoints) && m.datapoints.length > 0 ? (
                        <div className="spark">
                          {m.datapoints.map((pt, j) => (
                            <span
                              key={j}
                              style={{ height: `${Math.max(3, (pt / Math.max(...m.datapoints, 1)) * 24)}px` }}
                            />
                          ))}
                        </div>
                      ) : (
                        <div className="metric-no-chart">No datapoint series available</div>
                      )}
                    </div>
                  ))}
                </>
              )}
            </div>
          )}

          {tab === 'resources' && (
            <div className="modal-pane active">
              <div className="block-label">Affected resources · {finding.resourceCount}</div>
              <div className="resource-id-list">
                {resourceIds.length === 0 ? (
                  <div className="evidence-empty">No resource identifiers recorded.</div>
                ) : (
                  resourceIds.map((rid) => (
                    <div className="resource-id-row mono" key={rid}>
                      {truncateId(rid, 32)}
                    </div>
                  ))
                )}
              </div>
              {topo.length > 0 && (
                <>
                  <div className="block-label">Dependencies</div>
                  <div className="topo-grid">
                    {topo.map((t, i) => (
                      <div className="topo-item" key={i}>
                        <div className="k">{t.k}</div>
                        <div className="v">{t.v}</div>
                      </div>
                    ))}
                  </div>
                </>
              )}
              {finding.topoWarn && (
                <div className="warn-box">
                  <span>⚠️</span>
                  <span>{finding.topoWarn}</span>
                </div>
              )}
            </div>
          )}

          {tab === 'cost' && (
            <div className="modal-pane active">
              <div className="block-label">Cost context</div>
              <div className="cost-grid">
                {costCards.map((c, i) => (
                  <div className="cost-card" key={i}>
                    <div className="k">{c.k}</div>
                    <div className="v">{c.v}</div>
                  </div>
                ))}
              </div>
              <div className="block-label">Status</div>
              <div className="status-pending">{finding.costStatus}</div>
            </div>
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