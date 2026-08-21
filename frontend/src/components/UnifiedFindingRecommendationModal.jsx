import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'

import {
  formatMoneyOrDash,
  sevClass,
  sevLabel,
  statusLabel,
  truncateId,
} from '../utils/format'

import { attributionInfo } from '../mappers/findings'

import { explainRecommendation } from '../api/client'

function safeArray(value) {
  return Array.isArray(value)
    ? value
    : []
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
    metric.actual !== undefined &&
    metric.actual !== ''
  ) {
    return metric.actual
  }

  return '—'
}

function resolveFindingCost(finding) {
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
    billing.analysis_period_cost,
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
    'optimization'
  )
}

function normalizeResources(
  finding,
) {
  if (!finding) {
    return []
  }

  /*
   * Preferred aggregated form from
   * the backend:
   * resource_ids + resource_count
   */
  if (
    Array.isArray(
      finding.resourceIds,
    )
  ) {
    return finding.resourceIds.map(
      (id) => ({
        id,
        type:
          finding.resource_type,
        region:
          finding.region,
      }),
    )
  }

  if (
    Array.isArray(
      finding.resource_ids,
    )
  ) {
    return finding.resource_ids.map(
      (id) => ({
        id,
        type:
          finding.resource_type,
        region:
          finding.region,
      }),
    )
  }

  if (
    Array.isArray(
      finding.resources,
    )
  ) {
    return finding.resources
  }

  if (
    finding.resource_id
  ) {
    return [
      {
        id:
          finding.resource_id,
        type:
          finding.resource_type,
        region:
          finding.region,
      },
    ]
  }

  if (
    finding.resource
  ) {
    return [
      {
        id:
          finding.resource,
        type:
          finding.resource_type,
        region:
          finding.region,
      },
    ]
  }

  return []
}

function normalizeEvidence(
  finding,
) {
  if (!finding) {
    return []
  }

  /*
   * Current frontend mapper.
   */
  if (
    Array.isArray(
      finding.evidenceItems,
    )
  ) {
    return finding.evidenceItems
  }

  /*
   * Legacy frontend mapper.
   */
  if (
    Array.isArray(
      finding.evidence_items,
    )
  ) {
    return finding.evidence_items
  }

  /*
   * Direct evidence list.
   */
  if (
    Array.isArray(
      finding.evidence,
    )
  ) {
    return finding.evidence
  }

  /*
   * Current backend presenter can provide
   * evidence as an object.
   */
  if (
    finding.evidence &&
    typeof finding.evidence ===
      'object'
  ) {
    const evidence =
      finding.evidence

    if (
      Array.isArray(
        evidence.items,
      )
    ) {
      return evidence.items
    }

    if (
      Array.isArray(
        evidence.conditions,
      )
    ) {
      return evidence.conditions
    }

    if (
      Array.isArray(
        evidence.statements,
      )
    ) {
      return evidence.statements
    }
  }

  /*
   * Legacy condition-group format.
   */
  const groups =
    safeArray(
      finding.conditionGroups ||
        finding.condition_groups,
    )

  const result = []

  for (
    const group of groups
  ) {
    for (
      const statement of safeArray(
        group?.statements,
      )
    ) {
      const status =
        statement?.status ||
        statement?.statusClass ||
        'unknown'

      const supportsFinding =
        statement?.supports_finding !==
          null &&
        statement?.supports_finding !==
          undefined
          ? statement.supports_finding
          : (
              status ===
                'passed' ||
              status === 'true' ||
              status ===
                'detected'
            )

      result.push({
        resourceId:
          group?.resourceId ||
          group?.resource_id ||
          statement?.resourceId ||
          statement?.resource_id ||
          '',

        label:
          statement?.label ||
          statement?.name ||
          'Condition',

        expected:
          statement?.expected,

        actual:
          statement?.actual ??
          statement?.observed,

        status,

        supports_finding:
          supportsFinding,

        description:
          statement?.description ||
          '',
      })
    }
  }

  return result
}

function normalizeMetrics(
  finding,
) {
  return safeArray(
    finding?.metrics,
  )
}

function normalizeRecommendationImpact(
  recommendation,
) {
  if (!recommendation) {
    return []
  }

  const financial =
    recommendation.financial_impact ||
    recommendation.financialImpact ||
    {}

  const rows = []

  const cost =
    financial.observed_monthly_cost

  const estimatedSavings =
    financial.estimated_monthly_savings

  const savingsConfidence =
    financial.savings_confidence

  const savingsBasis =
    financial.savings_basis

  const resourceCount =
    recommendation.affectedResourceCount ??
    recommendation.affected_resource_count ??
    (
      Array.isArray(
        recommendation.affected_resources,
      )
        ? recommendation
            .affected_resources
            .length
        : null
    )

  const confidence =
    recommendation.confidence

  const priority =
    recommendation.priority ||
    recommendation.severity

  const scope =
    recommendation.scope ||
    recommendation.recommendation_scope

  const service =
    recommendation.service

  rows.push({
    id:
      'observed-cost',

    label:
      'Observed cost',

    value:
      formatMoneyOrDash(
        cost,
      ),

    big:
      true,
  })

  rows.push({
    id:
      'potential-savings',

    label:
      'Potential savings',

    value:
      estimatedSavings ==
        null
        ? savingsBasis ===
          'cost_not_resource_attributed'
          ? 'Not resource-attributed'
          : savingsBasis ===
              'cost_unknown' ||
            savingsBasis ===
              'cost_invalid'
            ? 'Cost unknown'
            : 'Not quantified'
        : Number(
              estimatedSavings,
            ) > 0
          ? `Up to ${formatMoneyOrDash(
              estimatedSavings,
            )}`
          : 'None identified yet',

    big:
      true,
  })

  if (
    savingsBasis ===
    'cost_not_resource_attributed'
  ) {
    rows.push({
      id:
        'savings-basis-note',

      label:
        'Why not quantified',

      value:
        'This cost covers a usage type/region, not confirmed as this one resource’s share.',
    })
  }

  if (savingsConfidence) {
    rows.push({
      id:
        'savings-confidence',

      label:
        'Savings confidence',

      value:
        String(
          savingsConfidence,
        )
          .charAt(0)
          .toUpperCase() +
        String(
          savingsConfidence,
        ).slice(1),
    })
  }

  if (
    resourceCount !==
      null &&
    resourceCount !==
      undefined &&
    resourceCount !==
      ''
  ) {
    rows.push({
      id:
        'affected-resources',

      label:
        'Affected resources',

      value:
        resourceCount,
    })
  }

  if (
    confidence !==
      null &&
    confidence !==
      undefined &&
    confidence !==
      ''
  ) {
    rows.push({
      id:
        'confidence',

      label:
        'Confidence',

      value:
        confidence,
    })
  }

  if (priority) {
    rows.push({
      id:
        'priority',

      label:
        'Priority',

      value:
        priority,
    })
  }

  if (scope) {
    rows.push({
      id:
        'scope',

      label:
        'Scope',

      value:
        scope,
    })
  }

  if (
    service &&
    service !== 'Unknown service'
  ) {
    rows.push({
      id:
        'service',

      label:
        'Service',

      value:
        service,
    })
  }

  return rows
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
            {columns.map(
              (column) => (
                <th
                  key={
                    column.key
                  }
                >
                  {column.label}
                </th>
              ),
            )}
          </tr>
        </thead>

        <tbody>
          {rows.map(
            (
              row,
              rowIndex,
            ) => (
              <tr
                key={
                  row.id ||
                  row.resourceId ||
                  row.key ||
                  rowIndex
                }
              >

                {columns.map(
                  (column) => (
                    <td
                      key={
                        column.key
                      }
                      className={
                        column.mono
                          ? 'mono'
                          : ''
                      }
                    >
                      {column.render
                        ? column.render(
                            row,
                          )
                        : valueOrDash(
                            row[
                              column.key
                            ],
                          )}
                    </td>
                  ),
                )}

              </tr>
            ),
          )}
        </tbody>

      </table>

    </div>
  )
}

function MetricChart({
  datapoints,
}) {
  const values =
    safeArray(
      datapoints,
    )
      .map(Number)
      .filter(
        Number.isFinite,
      )

  if (!values.length) {
    return (
      <span className="detail-no-trend">
        No trend data
      </span>
    )
  }

  const max =
    Math.max(
      ...values,
      1,
    )

  return (
    <div
      className="detail-spark"
      aria-label="Metric trend"
    >
      {values.map(
        (
          value,
          index,
        ) => (
          <span
            key={index}
            style={{
              height: `${Math.max(
                4,
                (
                  value /
                  max
                ) *
                  32,
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

function FindingView({
  finding,
  resources,
  evidence,
  metrics,
  onViewRecommendation,
  recommendationAvailable,
}) {
  const cost =
    resolveFindingCost(
      finding,
    )

  return (
    <>

      {/* Finding summary */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Finding summary"
          title="Assessment summary"
          description="Summary of the detected condition, severity, confidence, and financial context."
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

            <strong>
              {formatMoneyOrDash(cost)}
            </strong>

            {(() => {
              const scope =
                finding.costScope ||
                finding?.billingDetails
                  ?.attribution_scope ||
                finding?.billing_details
                  ?.attribution_scope

              if (!scope) {
                return null
              }

              const info =
                attributionInfo(scope)

              return (
                <span
                  title={info.tooltip}
                  style={{
                    fontSize: '0.75em',
                    opacity: 0.75,
                  }}
                >
                  {info.label}
                </span>
              )
            })()}
          </div>


 

        </div>

      </section>

      {/* Diagnosis */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Diagnosis"
          title="Assessment rationale"
          description="Explanation of the condition identified by the analyzer."
        />

        <div className="diag-reason">
          {finding.reason ||
            finding.description ||
            'No assessment rationale was recorded.'}
        </div>

      </section>

      {/* Evidence */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Evidence"
          title="Supporting evidence"
          description="Observed conditions and measurements that support this finding."
        />

        {evidence.length > 0 ? (
          <DetailTable
            rows={evidence}
            columns={[
              {
                key:
                  'resourceId',

                label:
                  'Resource',

                mono:
                  true,

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
            emptyText="No supporting evidence is available."
          />
        ) : (
          <div className="diag-reason">

            {Array.isArray(
              finding.evidenceSummary,
            )
              ? finding.evidenceSummary.join(
                  ' ',
                )
              : finding.reason ||
                'No detailed supporting evidence was recorded.'}

          </div>
        )}

      </section>

      {/* Resources */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Resources"
          title={`Affected resources · ${resources.length}`}
          description="AWS resources associated with this finding."
        />

        <DetailTable
          rows={resources}
          columns={[
            {
              key:
                'id',

              label:
                'Resource ID',

              mono:
                true,

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
                      row.resource_type ||
                      finding.resource_type,
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
          emptyText="No resource identifiers are associated with this finding."
        />

      </section>

      {/* Metrics */}

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

      {/* Analysis notes */}

      {finding.limitations?.length >
        0 && (
        <section className="detail-section">

          <SectionHeader
            eyebrow="/ Analysis notes"
            title="Limitations and constraints"
            description="Considerations that may affect interpretation of the finding."
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

      {/* Optional navigation to recommendation */}

      {recommendationAvailable &&
        onViewRecommendation && (
          <section className="detail-section">

            <SectionHeader
              eyebrow="/ Next action"
              title="Recommendation available"
              description="A corresponding optimization recommendation has been generated for this finding."
            />

            <button
              type="button"
              className="related-finding-card"
              onClick={() =>
                onViewRecommendation(
                  finding,
                )
              }
            >
              <strong>
                View recommendation
              </strong>

              <span>
                Review the proposed action
                and expected impact.
              </span>

              <span className="row-chevron">
                →
              </span>
            </button>

          </section>
        )}

    </>
  )
}

function RecommendationView({
  recommendation,
  relatedFinding,
  impactRows,
  onViewFinding,
  aiExplanation,
  aiLoading,
  aiUnavailable,
  onRegenerateExplanation,
}) {
  return (
    <>

      {/* Recommended action */}

      <section className="detail-section recommendation-highlight">

        <SectionHeader
          eyebrow="/ Recommendation"
          title="Recommended implementation"
          description="Action proposed by the optimization engine based on the analyzed finding."
        />

        <div className="diag-reason">

          {recommendation.action ||
            recommendation.description ||
            'No implementation action was recorded.'}

        </div>

      </section>

      {/* AI explanation */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ AI explanation"
          title="Plain-language explanation"
          description="Generated locally from the recommendation's own evidence. Does not decide eligibility, priority, or savings — those come from the deterministic engine above."
        />

        {aiExplanation ? (

          <div className="ai-explanation">

            <p>
              {aiExplanation.summary}
            </p>

            <p>
              <strong>Why: </strong>
              {aiExplanation.why}
            </p>

            <p>
              <strong>Next step: </strong>
              {aiExplanation.action}
            </p>

            <p>
              <strong>Risk: </strong>
              {aiExplanation.risk}
            </p>

            {aiExplanation.confidence_note && (
              <p className="impact-note">
                {aiExplanation.confidence_note}
              </p>
            )}

            <button
              type="button"
              className="small-btn"
              onClick={onRegenerateExplanation}
              disabled={aiLoading}
            >
              {aiLoading
                ? 'Regenerating…'
                : 'Regenerate explanation'}
            </button>

          </div>

        ) : aiLoading ? (

          <div className="detail-empty">
            Generating explanation locally…
          </div>

        ) : aiUnavailable ? (

          <div className="detail-empty">
            AI explanation is unavailable right now
            (the local Ollama runtime may not be
            running).{' '}
            <button
              type="button"
              className="small-btn"
              onClick={onRegenerateExplanation}
            >
              Retry
            </button>
          </div>

        ) : (

          <div className="detail-empty">
            No AI explanation has been generated yet.
          </div>

        )}

      </section>

      {/* Rationale */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Rationale"
          title="Recommendation rationale"
          description="Reasoning supporting the proposed optimization action."
        />

        <div className="diag-reason">

          {recommendation.reason ||
            recommendation.rationale ||
            recommendation.description ||
            'No recommendation rationale was recorded.'}

        </div>

      </section>

      {/* Financial impact */}

      {impactRows.length > 0 && (
        <section className="detail-section">

          <SectionHeader
            eyebrow="/ Financial impact"
            title="Estimated savings and scope"
            description="Estimated financial impact and operational scope associated with the recommendation."
          />

          <div className="impact-card-grid">

            {impactRows.map(
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

          <p className="impact-note">
            Estimated from observed AWS cost and analyzer evidence.
            Actual savings require validation before implementation.
          </p>

        </section>
      )}

      {/* Implementation notes */}

      {Array.isArray(
        recommendation.limitations,
      ) &&
        recommendation.limitations
          .length > 0 && (
          <section className="detail-section">

            <SectionHeader
              eyebrow="/ Implementation notes"
              title="Limitations and constraints"
              description="Considerations that should be reviewed before applying the recommendation."
            />

            <ul className="limit-list">

              {recommendation.limitations.map(
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

      {/* Status */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Recommendation status"
          title="Current status"
          description="Current lifecycle state of the recommendation."
        />

        <div className="status-pending">

          {statusLabel(
            recommendation.status ||
              'requires_validation',
          )}

        </div>

      </section>

      {/* Source finding */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Source finding"
          title="Finding associated with this recommendation"
          description="The finding that provided the primary basis for this recommendation."
        />

        {relatedFinding ? (
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
                'Optimization finding'}
            </strong>

            <span>
              {relatedFinding.service ||
                relatedFinding.resource_type ||
                'AWS resource'}

              {relatedFinding.region
                ? ` · ${relatedFinding.region}`
                : ''}
            </span>

            <span className="row-chevron">
              →
            </span>

          </button>
        ) : (
          <div className="detail-empty">
            No directly linked source finding
            is available.
          </div>
        )}

      </section>

    </>
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
  const modalRef =
    useRef(null)

  /*
   * Enforce exactly ONE modal mode.
   *
   * If a finding is present, show finding mode.
   * If there is no finding and a recommendation
   * is present, show recommendation mode.
   */
  const isFindingMode =
    Boolean(finding)

  const isRecommendationMode =
    !finding &&
    Boolean(recommendation)

  const resources =
    useMemo(
      () =>
        normalizeResources(
          finding,
        ),
      [finding],
    )

  const evidence =
    useMemo(
      () =>
        normalizeEvidence(
          finding,
        ),
      [finding],
    )

  const metrics =
    useMemo(
      () =>
        normalizeMetrics(
          finding,
        ),
      [finding],
    )

  const impactRows =
    useMemo(
      () =>
        normalizeRecommendationImpact(
          recommendation,
        ),
      [recommendation],
    )

  const recommendationId =
    isRecommendationMode
      ? recommendation?.id
      : null

  const [aiExplanation, setAiExplanation] =
    useState(
      recommendation?.ai_explanation ||
        null,
    )

  const [aiLoading, setAiLoading] =
    useState(false)

  const [aiUnavailable, setAiUnavailable] =
    useState(false)

  useEffect(() => {

    // Keyed ONLY on recommendationId. Do not add aiLoading/
    // aiExplanation/aiUnavailable to this dependency array --
    // setAiLoading(true) below would then re-trigger this same
    // effect before the fetch resolves, tearing down this closure
    // (cancelled = true) and silently discarding the real response
    // forever, leaving the UI stuck on "Generating explanation
    // locally..." even after the backend already answered.

    const cachedExplanation =
      recommendation?.ai_explanation ||
      null

    setAiExplanation(
      cachedExplanation,
    )

    setAiUnavailable(false)
    setAiLoading(false)

    if (
      !recommendationId ||
      cachedExplanation
    ) {
      return undefined
    }

    let cancelled = false

    setAiLoading(true)

    explainRecommendation(
      recommendationId,
    )
      .then((result) => {

        if (cancelled) {
          return
        }

        if (result?.ai_explanation) {
          setAiExplanation(
            result.ai_explanation,
          )
        } else {
          setAiUnavailable(true)
        }
      })
      .catch(() => {

        if (!cancelled) {
          setAiUnavailable(true)
        }
      })
      .finally(() => {

        if (!cancelled) {
          setAiLoading(false)
        }
      })

    return () => {
      cancelled = true
    }

  }, [recommendationId])

  function handleRegenerateExplanation() {

    if (!recommendationId) {
      return
    }

    setAiLoading(true)
    setAiUnavailable(false)

    explainRecommendation(
      recommendationId,
      { force: true },
    )
      .then((result) => {

        if (result?.ai_explanation) {
          setAiExplanation(
            result.ai_explanation,
          )
        } else {
          setAiUnavailable(true)
        }
      })
      .catch(() => {
        setAiUnavailable(true)
      })
      .finally(() => {
        setAiLoading(false)
      })
  }

  useEffect(() => {
    if (
      !isFindingMode &&
      !isRecommendationMode
    ) {
      return undefined
    }

    function handleKeyDown(
      event,
    ) {
      if (
        event.key ===
        'Escape'
      ) {
        onClose()
        return
      }

      if (
        event.key !==
        'Tab'
      ) {
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

      if (
        !focusable.length
      ) {
        return
      }

      const first =
        focusable[0]

      const last =
        focusable[
          focusable.length -
            1
        ]

      if (
        event.shiftKey &&
        document.activeElement ===
          first
      ) {
        event.preventDefault()
        last.focus()
      } else if (
        !event.shiftKey &&
        document.activeElement ===
          last
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

    requestAnimationFrame(
      () => {
        modalRef.current
          ?.querySelector(
            '.modal-close',
          )
          ?.focus()
      },
    )

    return () => {
      document.removeEventListener(
        'keydown',
        handleKeyDown,
      )

      document.body.style.overflow =
        previousOverflow
    }
  }, [
    isFindingMode,
    isRecommendationMode,
    onClose,
  ])

  if (
    !isFindingMode &&
    !isRecommendationMode
  ) {
    return null
  }

  const title =
    isFindingMode
      ? (
          finding?.fullTitle ||
          finding?.title ||
          'Optimization finding'
        )
      : (
          recommendation?.title ||
          recommendation?.name ||
          'Optimization recommendation'
        )

  const service =
    finding?.service ||
    finding?.resource_type ||
    recommendation?.service ||
    recommendation?.resource_type

  const region =
    finding?.region ||
    recommendation?.region

  const severity =
    finding?.severity ||
    recommendation?.priority ||
    'medium'

  /*
   * Only the finding view can navigate to its
   * associated recommendation.
   */
  const relatedRecommendation =
    isFindingMode
      ? (
          finding?.relatedRecommendation ||
          null
        )
      : null

  return (
    <div
      className="overlay open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="optimization-modal-title"
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
          isRecommendationMode
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

              {isFindingMode
                ? '/ Finding details'
                : '/ Recommendation details'}

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
                id="optimization-modal-title"
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

                {isFindingMode && (
                  <span>
                    {resources.length}{' '}
                    affected resource
                    {resources.length ===
                    1
                      ? ''
                      : 's'}
                  </span>
                )}

                {isRecommendationMode &&
                  recommendation?.scope && (
                    <span>
                      Scope:{' '}
                      {recommendation.scope}
                    </span>
                  )}

              </div>

            </div>

          </div>
        </div>

        {/* Body */}

        <div className="modal-body">

          {isFindingMode && (
            <FindingView
              finding={finding}
              resources={
                resources
              }
              evidence={
                evidence
              }
              metrics={
                metrics
              }
              recommendationAvailable={
                Boolean(
                  relatedRecommendation,
                )
              }
              onViewRecommendation={
                relatedRecommendation
                  ? onViewRecommendation
                  : null
              }
            />
          )}

          {isRecommendationMode && (
            <RecommendationView
              recommendation={
                recommendation
              }
              relatedFinding={
                relatedFinding
              }
              impactRows={
                impactRows
              }
              onViewFinding={
                onViewFinding
              }
              aiExplanation={
                aiExplanation
              }
              aiLoading={
                aiLoading
              }
              aiUnavailable={
                aiUnavailable
              }
              onRegenerateExplanation={
                handleRegenerateExplanation
              }
            />
          )}

        </div>

        {/* Footer */}

        <div className="modal-foot">

          <button
            type="button"
            className="btn btn-outline"
            onClick={onClose}
          >
            Close
          </button>

          {isFindingMode &&
            relatedRecommendation &&
            onViewRecommendation && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() =>
                  onViewRecommendation(
                    finding,
                  )
                }
              >
                View recommendation
              </button>
            )}

          {isRecommendationMode &&
            relatedFinding &&
            onViewFinding && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() =>
                  onViewFinding(
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