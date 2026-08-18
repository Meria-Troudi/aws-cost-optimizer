import {
  useEffect,
  useMemo,
  useRef,
} from 'react'

import {
  formatMoneyOrDash,
  sevClass,
  sevLabel,
  statusLabel,
  truncateId,
} from '../utils/format'

function safeArray(value) {
  return Array.isArray(value) ? value : []
}

function valueOrDash(value) {
  if (
    value === null ||
    value === undefined ||
    value === ''
  ) {
    return '—'
  }

  return String(value)
}

function formatMetricValue(metric) {
  if (!metric) {
    return '—'
  }

  if (
    metric.value !== null &&
    metric.value !== undefined &&
    metric.value !== ''
  ) {
    return metric.value
  }

  if (
    metric.actual !== null &&
    metric.actual !== undefined
  ) {
    return metric.actual
  }

  return '—'
}

function normalizeResources(finding) {
  if (!finding) {
    return []
  }

  if (Array.isArray(finding.resources)) {
    return finding.resources
  }

  if (Array.isArray(finding.resourceIds)) {
    return finding.resourceIds.map((id) => ({
      id,
    }))
  }

  if (Array.isArray(finding.resource_ids)) {
    return finding.resource_ids.map((id) => ({
      id,
    }))
  }

  if (finding.resource) {
    return [
      {
        id: finding.resource,
      },
    ]
  }

  if (finding.resource_id) {
    return [
      {
        id: finding.resource_id,
      },
    ]
  }

  return []
}

function normalizeEvidence(finding) {
  if (!finding) {
    return []
  }

  if (Array.isArray(finding.evidenceItems)) {
    return finding.evidenceItems
  }

  if (Array.isArray(finding.evidence_items)) {
    return finding.evidence_items
  }

  const groups = safeArray(
    finding.conditionGroups ||
      finding.condition_groups,
  )

  const result = []

  groups.forEach((group) => {
    safeArray(group.statements).forEach(
      (statement) => {
        const status =
          statement.status ||
          statement.statusClass ||
          'unknown'

        const supportsFinding =
          statement.supports_finding !== null &&
          statement.supports_finding !== undefined
            ? statement.supports_finding
            : status === 'passed' ||
              status === 'true'

        result.push({
          resourceId:
            group.resourceId ||
            group.resource_id ||
            statement.resourceId ||
            statement.resource_id ||
            '',

          label:
            statement.label ||
            statement.name ||
            'Evidence',

          expected:
            statement.expected,

          actual:
            statement.actual ??
            statement.observed,

          status,

          supports_finding:
            supportsFinding,

          description:
            statement.description ||
            '',
        })
      },
    )
  })

  return result
}

function normalizeMetrics(finding) {
  return safeArray(
    finding?.metrics,
  )
}

function normalizeCostCards(finding) {
  return safeArray(
    finding?.costCards ||
      finding?.cost_cards,
  )
}

function normalizeRecommendationImpact(
  recommendation,
) {
  if (!recommendation) {
    return []
  }

  const rows = []

  const financial =
    recommendation.financial_impact ||
    recommendation.financialImpact ||
    {}

  const monthlySavings =
    recommendation.estimated_monthly_savings ??
    recommendation.estimatedMonthlySavings ??
    recommendation.monthly_savings ??
    recommendation.monthlySavings ??
    financial.monthly_savings ??
    financial.estimated_monthly_savings

  const annualSavings =
    recommendation.estimated_annual_savings ??
    recommendation.estimatedAnnualSavings ??
    recommendation.annual_savings ??
    recommendation.annualSavings ??
    financial.annual_savings ??
    financial.estimated_annual_savings

  const affectedResources =
    recommendation.affectedResourceCount ??
    recommendation.affected_resource_count

  const confidence =
    recommendation.confidence

  const priority =
    recommendation.priority ||
    recommendation.severity

  const resourceCount =
    recommendation.affected_resources?.length ||
    affectedResources

  if (
    monthlySavings !== null &&
    monthlySavings !== undefined &&
    monthlySavings !== ''
  ) {
    rows.push({
      id: 'monthly-savings',
      label: 'Estimated monthly savings',
      value: formatMoneyOrDash(
        monthlySavings,
      ),
      big: true,
    })
  }

  if (
    annualSavings !== null &&
    annualSavings !== undefined &&
    annualSavings !== ''
  ) {
    rows.push({
      id: 'annual-savings',
      label: 'Estimated annual savings',
      value: formatMoneyOrDash(
        annualSavings,
      ),
      big: true,
    })
  }

  if (
    resourceCount !== null &&
    resourceCount !== undefined &&
    resourceCount !== ''
  ) {
    rows.push({
      id: 'affected-resources',
      label: 'Affected resources',
      value: resourceCount,
    })
  }

  if (
    confidence !== null &&
    confidence !== undefined &&
    confidence !== ''
  ) {
    rows.push({
      id: 'confidence',
      label: 'Confidence',
      value: confidence,
    })
  }

  if (priority) {
    rows.push({
      id: 'priority',
      label: 'Priority',
      value: priority,
    })
  }

  if (recommendation.scope) {
    rows.push({
      id: 'scope',
      label: 'Recommendation scope',
      value: recommendation.scope,
    })
  }

  return rows
}

function resolveCurrentCost(finding) {
  const billing =
    finding?.billingDetails ||
    finding?.billing_details ||
    {}

  const impact =
    finding?.impact ||
    {}

  const values = [
    finding?.cost,
    billing.amount,
    billing.cost,
    billing.period_cost,
    impact.period_cost,
    impact.cost,
  ]

  for (const value of values) {
    const amount = Number(value)

    if (
      Number.isFinite(amount)
    ) {
      return amount
    }
  }

  return null
}

function resolveCategory(finding) {
  return (
    finding?.category ||
    finding?.finding_category ||
    (
      finding?.findingType
        ? 'Optimization'
        : '—'
    )
  )
}

function DetailTable({
  columns,
  rows,
  emptyText = 'No data available.',
}) {
  if (!rows.length) {
    return (
      <div className="detail-empty">
        {emptyText}
      </div>
    )
  }

  return (
    <div className="detail-table-wrap">
      <table className="detail-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>
                {column.label}
              </th>
            ))}
          </tr>
        </thead>

        <tbody>
          {rows.map((row, rowIndex) => (
            <tr
              key={
                row.id ||
                row.resourceId ||
                row.key ||
                rowIndex
              }
            >
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={
                    column.mono
                      ? 'mono'
                      : ''
                  }
                >
                  {column.render
                    ? column.render(row)
                    : valueOrDash(
                        row[column.key],
                      )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function MetricChart({
  datapoints,
}) {
  const values = safeArray(
    datapoints,
  )
    .map(Number)
    .filter(Number.isFinite)

  if (!values.length) {
    return (
      <span className="detail-no-trend">
        No trend data
      </span>
    )
  }

  const max = Math.max(
    ...values,
    1,
  )

  return (
    <div
      className="detail-spark"
      aria-label="Metric trend"
    >
      {values.map(
        (value, index) => (
          <span
            key={index}
            style={{
              height: `${Math.max(
                4,
                (value / max) * 32,
              )}px`,
            }}
          />
        ),
      )}
    </div>
  )
}

function SectionHeader({
  eyebrow,
  title,
  description,
}) {
  return (
    <div className="detail-section-head">
      <div className="block-label">
        {eyebrow}
      </div>

      {title && (
        <h4 className="detail-section-title">
          {title}
        </h4>
      )}

      {description && (
        <p className="detail-section-description">
          {description}
        </p>
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
  onViewRecommendation,
}) {
  const modalRef = useRef(null)

  const showFinding =
    Boolean(finding)

  const showRecommendation =
    Boolean(recommendation)

  const resources = useMemo(
    () =>
      normalizeResources(
        finding,
      ),
    [finding],
  )

  const evidence = useMemo(
    () =>
      normalizeEvidence(
        finding,
      ),
    [finding],
  )

  const metrics = useMemo(
    () =>
      normalizeMetrics(
        finding,
      ),
    [finding],
  )

  const costCards = useMemo(
    () =>
      normalizeCostCards(
        finding,
      ),
    [finding],
  )

  const recommendationImpact =
    useMemo(
      () =>
        normalizeRecommendationImpact(
          recommendation,
        ),
      [recommendation],
    )

  useEffect(() => {
    if (
      !showFinding &&
      !showRecommendation
    ) {
      return undefined
    }

    function handleKeyDown(event) {
      if (event.key === 'Escape') {
        onClose()
        return
      }

      if (event.key !== 'Tab') {
        return
      }

      const root =
        modalRef.current

      if (!root) {
        return
      }

      const focusable =
        root.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        )

      if (!focusable.length) {
        return
      }

      const first =
        focusable[0]

      const last =
        focusable[
          focusable.length - 1
        ]

      if (
        event.shiftKey &&
        document.activeElement === first
      ) {
        event.preventDefault()
        last.focus()
      } else if (
        !event.shiftKey &&
        document.activeElement === last
      ) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener(
      'keydown',
      handleKeyDown,
    )

    const previousOverflow =
      document.body.style.overflow

    document.body.style.overflow =
      'hidden'

    requestAnimationFrame(() => {
      modalRef.current
        ?.querySelector(
          '.modal-close',
        )
        ?.focus()
    })

    return () => {
      document.removeEventListener(
        'keydown',
        handleKeyDown,
      )

      document.body.style.overflow =
        previousOverflow
    }
  }, [
    showFinding,
    showRecommendation,
    onClose,
  ])

  if (
    !showFinding &&
    !showRecommendation
  ) {
    return null
  }

  const title =
    finding?.fullTitle ||
    finding?.title ||
    recommendation?.title ||
    recommendation?.name ||
    'Optimization details'

  const service =
    finding?.service ||
    recommendation?.service

  const region =
    finding?.region ||
    recommendation?.region

  const severity =
    finding?.severity ||
    recommendation?.priority ||
    'medium'

  const isRecommendationOnly =
    showRecommendation &&
    !showFinding

  const modalType =
    showFinding
      ? 'Finding details'
      : 'Recommendation details'

  const currentCost =
    resolveCurrentCost(
      finding,
    )

  return (
    <div
      className="overlay open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="finding-modal-title"
      onClick={(event) => {
        if (
          event.target ===
          event.currentTarget
        ) {
          onClose()
        }
      }}
    >
      <div
        ref={modalRef}
        className={`modal modal-large ${
          showRecommendation
            ? 'modal-recommendation'
            : 'modal-finding'
        }`}
      >

        {/* Header */}

        <div className="modal-head">

          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            aria-label="Close details"
          >
            ×
          </button>

          <div className="modal-eyebrow">

            <span className="modal-context-label">
              / {modalType}
            </span>

            <span
              className={`sev-badge ${sevClass(
                severity,
              )}`}
            >
              {sevLabel(
                severity,
              )}
            </span>

          </div>

          <div className="modal-title-row">
            <div>

              <div
                className="modal-title"
                id="finding-modal-title"
              >
                {title}
              </div>

              <div className="modal-meta">

                {service && (
                  <span>
                    {service}
                  </span>
                )}

                {region && (
                  <span>
                    Region{' '}
                    <span className="mono">
                      {region}
                    </span>
                  </span>
                )}

                {showFinding && (
                  <span>
                    {resources.length}{' '}
                    affected resource
                    {resources.length ===
                    1
                      ? ''
                      : 's'}
                  </span>
                )}

                {isRecommendationOnly &&
                  recommendation?.scope && (
                    <span>
                      {recommendation.scope}
                    </span>
                  )}

              </div>

            </div>
          </div>
        </div>

        <div className="modal-body">

          {/* Finding */}

          {showFinding && (
            <>

              <section className="detail-section">

                <SectionHeader
                  eyebrow="/ Finding summary"
                  title="Assessment summary"
                  description="Summary of the detected condition, its severity, and its financial context."
                />

                <div className="detail-summary-grid">

                  <div className="detail-summary-card">
                    <span>
                      Severity
                    </span>

                    <strong
                      className={`sev-badge ${sevClass(
                        finding.severity,
                      )}`}
                    >
                      {sevLabel(
                        finding.severity,
                      )}
                    </strong>
                  </div>

                  <div className="detail-summary-card">
                    <span>
                      Confidence
                    </span>

                    <strong>
                      {valueOrDash(
                        finding.confidence,
                      )}
                    </strong>
                  </div>

                  <div className="detail-summary-card">
                    <span>
                      Analysis-period cost
                    </span>

                    <strong className="mono">
                      {currentCost ===
                      null
                        ? '—'
                        : formatMoneyOrDash(
                            currentCost,
                          )}
                    </strong>
                  </div>

                  <div className="detail-summary-card">
                    <span>
                      Category
                    </span>

                    <strong>
                      {resolveCategory(
                        finding,
                      )}
                    </strong>
                  </div>

                </div>
              </section>

              <section className="detail-section">

                <SectionHeader
                  eyebrow="/ Diagnosis"
                  title="Assessment rationale"
                  description="Explanation of the condition detected by the analyzer."
                />

                <div className="diag-reason">
                  {finding.reason ||
                    finding.description ||
                    'No assessment rationale was recorded.'}
                </div>

              </section>

              <section className="detail-section">

                <SectionHeader
                  eyebrow="/ Evidence"
                  title="Supporting evidence"
                  description="Observed conditions and measurements used to support the finding."
                />

                {evidence.length > 0 ? (
                  <DetailTable
                    rows={evidence}
                    emptyText="No supporting evidence is available."
                    columns={[
                      {
                        key:
                          'resourceId',
                        label:
                          'Resource',
                        mono: true,
                        render:
                          (row) =>
                            row.resourceId
                              ? truncateId(
                                  row.resourceId,
                                  28,
                                )
                              : '—',
                      },

                      {
                        key:
                          'label',
                        label:
                          'Condition',
                      },

                      {
                        key:
                          'expected',
                        label:
                          'Expected',
                      },

                      {
                        key:
                          'actual',
                        label:
                          'Observed',
                      },

                      {
                        key:
                          'status',
                        label:
                          'Status',
                        render:
                          (row) => (
                            <span
                              className={
                                row.supports_finding
                                  ? 'evidence-pass'
                                  : 'evidence-neutral'
                              }
                            >
                              {valueOrDash(
                                row.status,
                              )}
                            </span>
                          ),
                      },
                    ]}
                  />
                ) : (
                  <div className="diag-reason">
                    {finding.reason ||
                      finding.description ||
                      finding.evidenceSummary ||
                      'No detailed supporting evidence was recorded.'}
                  </div>
                )}

              </section>

              <section className="detail-section">

                <SectionHeader
                  eyebrow="/ Resources"
                  title={`Affected resources · ${resources.length}`}
                  description="AWS resources associated with the finding."
                />

                <DetailTable
                  rows={resources}
                  emptyText="No resource identifiers are associated with this finding."
                  columns={[
                    {
                      key: 'id',
                      label:
                        'Resource ID',
                      mono: true,
                      render:
                        (row) =>
                          truncateId(
                            row.id ||
                              row.resource_id ||
                              row.resource ||
                              '—',
                            42,
                          ),
                    },

                    {
                      key:
                        'type',
                      label:
                        'Type',
                      render:
                        (row) =>
                          valueOrDash(
                            row.type ||
                              row.resource_type,
                          ),
                    },

                    {
                      key:
                        'region',
                      label:
                        'Region',
                      render:
                        (row) =>
                          valueOrDash(
                            row.region ||
                              finding.region,
                          ),
                    },

                    {
                      key:
                        'status',
                      label:
                        'Status',
                    },
                  ]}
                />

              </section>

              {metrics.length > 0 && (
                <section className="detail-section">

                  <SectionHeader
                    eyebrow="/ Metrics"
                    title="Observed performance"
                    description="Utilization and performance measurements collected during the analysis."
                  />

                  <DetailTable
                    rows={metrics}
                    columns={[
                      {
                        key:
                          'name',
                        label:
                          'Metric',
                      },

                      {
                        key:
                          'value',
                        label:
                          'Value',
                        render:
                          (row) =>
                            formatMetricValue(
                              row,
                            ),
                      },

                      {
                        key:
                          'unit',
                        label:
                          'Unit',
                      },

                      {
                        key:
                          'period',
                        label:
                          'Period',
                      },

                      {
                        key:
                          'datapoints',
                        label:
                          'Trend',
                        render:
                          (row) => (
                            <MetricChart
                              datapoints={
                                row.datapoints
                              }
                            />
                          ),
                      },
                    ]}
                  />

                </section>
              )}

              {finding.limitations?.length >
                0 && (
                <section className="detail-section">

                  <SectionHeader
                    eyebrow="/ Analysis notes"
                    title="Limitations and constraints"
                    description="Important considerations that may affect the interpretation or implementation of this finding."
                  />

                  <ul className="limit-list">
                    {finding.limitations.map(
                      (
                        item,
                        index,
                      ) => (
                        <li
                          key={
                            index
                          }
                        >
                          {item}
                        </li>
                      ),
                    )}
                  </ul>

                </section>
              )}

            </>
          )}

          {/* Recommendation */}

          {showRecommendation && (
            <>

              <section className="detail-section recommendation-highlight">

                <SectionHeader
                  eyebrow="/ Recommended action"
                  title="Recommended implementation"
                  description="Action proposed by the optimization engine based on the available evidence."
                />

                <div className="diag-reason">
                  {recommendation.action ||
                    recommendation.description ||
                    recommendation.recommendation ||
                    'No implementation action was recorded.'}
                </div>

              </section>

              <section className="detail-section">

                <SectionHeader
                  eyebrow="/ Rationale"
                  title="Recommendation rationale"
                  description="Reasoning supporting the proposed optimization action."
                />

                <div className="diag-reason">
                  {recommendation.rationale ||
                    recommendation.reason ||
                    'No recommendation rationale was recorded.'}
                </div>

              </section>

              {recommendationImpact.length >
                0 && (
                <section className="detail-section">

                  <SectionHeader
                    eyebrow="/ Expected impact"
                    title="Potential savings and scope"
                    description="Estimated financial impact and operational scope associated with the recommendation."
                  />

                  <div className="impact-card-grid">

                    {recommendationImpact.map(
                      (row) => (
                        <div
                          className={`impact-card ${
                            row.big
                              ? 'impact-card-big'
                              : ''
                          }`}
                          key={
                            row.id
                          }
                        >

                          <span>
                            {row.label}
                          </span>

                          <strong
                            className={
                              row.big
                                ? 'mono'
                                : ''
                            }
                          >
                            {row.value}
                          </strong>

                        </div>
                      ),
                    )}

                  </div>

                </section>
              )}

              <section className="detail-section">

                <SectionHeader
                  eyebrow="/ Recommendation status"
                  title="Current status"
                  description="Current lifecycle state of the recommendation."
                />

                <div className="status-pending">
                  {statusLabel(
                    recommendation.status,
                  )}
                </div>

              </section>

              {relatedFinding && (
                <section className="detail-section">

                  <SectionHeader
                    eyebrow="/ Evidence link"
                    title="Source finding"
                    description="Finding that provided the primary evidence for this recommendation."
                  />

                  <button
                    type="button"
                    className="related-finding-card"
                    onClick={() =>
                      onViewFinding?.(
                        relatedFinding,
                      )
                    }
                  >

                    <strong>
                      {relatedFinding.fullTitle ||
                        relatedFinding.title ||
                        'Finding'}
                    </strong>

                    <span>
                      {relatedFinding.service ||
                        ''}
                      {relatedFinding.region
                        ? ` · ${relatedFinding.region}`
                        : ''}
                    </span>

                    <span className="row-chevron">
                      →
                    </span>

                  </button>

                </section>
              )}

              {!relatedFinding && (
                <div className="warn-box">
                  <span>
                    !
                  </span>

                  <span>
                    No directly linked finding
                    is available. Review the
                    recommendation and supporting
                    evidence before implementation.
                  </span>
                </div>
              )}

            </>
          )}

        </div>

        <div className="modal-foot">

          <button
            type="button"
            className="btn btn-outline"
            onClick={onClose}
          >
            Close
          </button>

          {showFinding &&
            onViewRecommendation && (
              <button
                type="button"
                className="btn btn-outline"
                onClick={() =>
                  onViewRecommendation(
                    finding,
                  )
                }
              >
                View recommendation
              </button>
            )}

          {showFinding &&
            onViewFinding && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() =>
                  onViewFinding(
                    finding,
                  )
                }
              >
                Focus finding
              </button>
            )}

          {showRecommendation &&
            relatedFinding &&
            !showFinding && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() =>
                  onViewFinding?.(
                    relatedFinding,
                  )
                }
              >
                View source finding
              </button>
            )}

        </div>
      </div>
    </div>
  )
}