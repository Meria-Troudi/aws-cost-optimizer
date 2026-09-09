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

// The Evidence table's "Observed" column shows formatConditionValue()'s
// summary of a condition's value -- for a diagnostic dict with many
// keys (e.g. Transit Gateway's telemetry diagnostics) that summary can
// still run to a dozen+ "key: value" pairs. This is supporting
// evidence, not the primary content of the modal, so cap it rather
// than let one row's cell dominate the table.
function truncateObserved(value, max = 140) {
  const text = valueOrDash(value)

  if (text.length <= max) {
    return text
  }

  return `${text.slice(0, max).trimEnd()}…`
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
  // finding.cost is already the presenter's fully-resolved,
  // resource-attributed cost (or null when unattributable) -- see
  // backend/api/presenters/finding_presenter.py::_extract_cost. Falling
  // back to billing.amount here would silently resurrect a shared
  // collection-plan/service bucket total as if it were this resource's
  // own cost, exactly the bug that made a NAT Gateway with a $125.33
  // shared bill render as "$0.00" instead of "not available". Only
  // `impact` is a legitimate secondary source: it mirrors the same
  // resource-attributed value the presenter derived cost from.
  const impact =
    finding?.impact ||
    {}

  const values = [
    finding?.cost,
    impact.period_cost,
    impact.cost,
  ]

  for (const value of values) {
    if (value === null || value === undefined) {
      continue
    }

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
          finding.resourceTypeLabel ||
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
          finding.resourceTypeLabel ||
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
          finding.resourceTypeLabel ||
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
          finding.resourceTypeLabel ||
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

// financial.py's calculate_savings() explains *why* it couldn't quantify
// savings via savings_basis rather than just returning null -- surface
// that reason instead of the generic "Cost unavailable" for every case,
// since "cost_not_resource_attributed" (a shared cost line, not missing
// data) is a materially different situation from "cost_unknown".
const SAVINGS_UNAVAILABLE_REASONS = {
  cost_not_resource_attributed:
    'Shared cost, not isolated',
  target_cost_required:
    'No savings target set',
  resource_attributed_cost:
    'No savings target set',
}

function savingsUnavailableReason(basis) {
  return (
    SAVINGS_UNAVAILABLE_REASONS[basis] ||
    'Cost unavailable'
  )
}

const SCOPE_TYPE_LABELS = {
  resource: 'Resource',
  region: 'Region',
  account: 'Account',
  service: 'Service',
}

// recommendation.scope is a raw "<type>:<value>" persistence key (see
// resolve_persistence_scope() in the backend) -- its value format is
// whatever that resource type's own resource_id happens to be, which
// is a full ARN for some services (ELB, WAF) and a bare identifier for
// others (Aurora, RDS). Rendered as-is, that reads as an inconsistent
// mix of very long and very short "Scope:" lines. This extracts one
// consistent short label + value for display, keeping the raw value
// available via the title attribute for anyone who needs the full ARN.
function describeScope(scope, { region } = {}) {
  if (!scope) {
    return null
  }

  const separatorIndex = scope.indexOf(':')

  const type =
    separatorIndex === -1
      ? scope
      : scope.slice(0, separatorIndex)

  const value =
    separatorIndex === -1
      ? ''
      : scope.slice(separatorIndex + 1)

  // Already shown as its own "Region <eu-west-1>" chip right next to
  // this one -- a region-scoped recommendation's Scope line would just
  // repeat it.
  if (type === 'region' && value && value === region) {
    return null
  }

  let displayValue = value

  if (value.startsWith('arn:')) {
    const segments = value.split(/[/:]/).filter(Boolean)

    let candidate = segments[segments.length - 1] || value

    // Many ARNs end in an opaque hex/UUID suffix after the actual
    // resource name (e.g. .../app/CITO-COLLINE-TEST-ALB/1c07ab6e6f8049c8,
    // .../webacl/CITO-TEST-WebACL/56e39661-9817-...) -- prefer the name
    // segment before it over the meaningless id.
    const strippedCandidate = candidate.replace(/-/g, '')

    const candidateIsOpaqueId =
      strippedCandidate.length >= 8 &&
      /^[0-9a-f]+$/i.test(strippedCandidate)

    if (candidateIsOpaqueId && segments.length > 1) {
      candidate = segments[segments.length - 2]
    }

    displayValue = candidate
  }

  return {
    label: SCOPE_TYPE_LABELS[type] || 'Scope',
    value: displayValue || scope,
    full: scope,
  }
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

  // Costs whose basis marks them as a shared/unattributed bucket (see
  // savingsUnavailableReason below) are shown under "Observed cost" for
  // context, but must never feed the "up to $X" upper-bound fallback --
  // that bucket total can be dominated by OTHER resources entirely (e.g.
  // a NAT gateway bucket split across several gateways, or an idle IP's
  // cost mixed with in-use IPs), so it is not a valid ceiling for THIS
  // resource's own potential savings.
  const costIsResourceAttributed =
    savingsBasis !== 'cost_not_resource_attributed' &&
    savingsBasis !== 'billing_usage_type_mismatch'

  /*
   * Potential savings uses the simplest defensible logic: a resource
   * that costs $X can save at most the cost currently being spent on
   * it. When the deterministic engine confirms a numeric savings it is
   * used directly; otherwise the resource's own observed cost is the
   * upper bound, but only when that cost is actually this resource's
   * own (not a shared bucket). Never "Not quantified" / "Requires
   * manual review."
   */
  const savingsAmount =
    estimatedSavings != null &&
    Number(estimatedSavings) > 0
      ? Number(estimatedSavings)
      : costIsResourceAttributed &&
          cost != null &&
          Number(cost) > 0
        ? Number(cost)
        : null

  rows.push({
    id:
      'potential-savings',

    label:
      'Potential savings',

    value:
      savingsAmount != null
        ? `Up to ${formatMoneyOrDash(
            savingsAmount,
          )}`
        : savingsUnavailableReason(
            savingsBasis,
          ),

    big:
      true,
  })

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

/*
 * The LLM's "action" field explains why the deterministic plan's
 * validation steps apply here -- it must never contain AWS operations
 * or commands (see aws_cost_optimizer/recommendations/llm/prompt.py
 * section 3 and llm/guard.py's unconditional command detector, which
 * rejects the explanation outright if one slips through). This is
 * plain multi-step prose only; inline `backtick` spans still render as
 * inline code for things like resource IDs.
 */
function renderInlineCode(text, keyPrefix) {
  const parts = text.split(/(`[^`]+`)/g)

  return parts.map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length > 1) {
      return (
        <code key={`${keyPrefix}-${index}`}>
          {part.slice(1, -1)}
        </code>
      )
    }

    return part
  })
}

function ExplanationText({ text }) {
  if (!text) {
    return null
  }

  const lines = String(text).split(/\r?\n/)

  const blocks = []
  let buffer = []

  function flushParagraph() {
    if (buffer.length) {
      const joined = buffer.join(' ')
      blocks.push(
        <p key={`p-${blocks.length}`}>
          {renderInlineCode(joined, `p-${blocks.length}`)}
        </p>,
      )
      buffer = []
    }
  }

  // The model doesn't reliably separate steps with a blank line -- it
  // often uses a single newline between "1. ...", "2. ..." items.
  // Treat a recognized step marker as its own paragraph boundary too,
  // so numbered/bulleted steps still render as separate lines.
  const STEP_MARKER = /^(?:\d+[.)]|\[\d+\]|-|•)\s+\S/

  lines.forEach((rawLine, index) => {
    const line = rawLine.trim()

    if (!line) {
      flushParagraph()
      return
    }

    if (STEP_MARKER.test(line) && buffer.length) {
      flushParagraph()
    }

    buffer.push(line)
  })

  flushParagraph()

  return blocks
}

function SectionHeader({
  eyebrow,
  title,
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
              Analysis-period cost
            </span>

            <strong>
              {cost != null
                ? formatMoneyOrDash(cost)
                : finding?.billingDetails?.amount != null
                  ? `${formatMoneyOrDash(
                      Number(finding.billingDetails.amount),
                    )} `
                  : formatMoneyOrDash(cost)}
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

      {(finding.reason || finding.description) && (
        <section className="detail-section">

          <SectionHeader
            eyebrow="/ Diagnosis"
          />

          <div className="diag-reason">
            {finding.reason || finding.description}
          </div>

        </section>
      )}

      {/* Evidence */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Evidence"
          title="Supporting evidence"
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
                  'actual',

                label:
                  'Observed',

                render:
                  (row) => (
                    <span title={valueOrDash(row.actual)}>
                      {truncateObserved(row.actual)}
                    </span>
                  ),
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
                      finding.resourceTypeLabel ||
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

      {/* Optional navigation to recommendation */}

      {recommendationAvailable &&
        onViewRecommendation && (
          <section className="detail-section">

            <SectionHeader
              eyebrow="/ Next action"
              title="Recommendation available"
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

/*
 * Renders in the modal's dark right-hand rail, not in the main
 * scrolling column -- the AI explanation is commentary alongside the
 * deterministic recommendation, not another section in the same list.
 */
function AIExplanationRail({
  aiExplanation,
  aiLoading,
  aiUnavailable,
  aiSlow,
  aiError,
  onRegenerateExplanation,
}) {
  return (
    <div className="rail-section">

      {aiExplanation ? (

        <div className="ai-explanation">

          <p>
            {aiExplanation.summary}
          </p>

          <p>
            <strong>Why: </strong>
            {aiExplanation.why}
          </p>

          <div className="ai-explanation-action">
            <span className="ai-explanation-action-label">Next step</span>
            <ExplanationText text={aiExplanation.action} />
          </div>

          {Array.isArray(aiExplanation.what_to_verify) &&
            aiExplanation.what_to_verify.length > 0 && (
              <>
                <div className="ai-explanation-subhead">
                  What to verify
                </div>

                <ul className="limit-list">
                  {aiExplanation.what_to_verify.map((step, index) => (
                    <li key={`verify-${index}`}>{step}</li>
                  ))}
                </ul>
              </>
            )}

          {Array.isArray(aiExplanation.possible_actions) &&
            aiExplanation.possible_actions.length > 0 && (
              <>
                <div className="ai-explanation-subhead">
                  Possible actions
                </div>

                <ul className="limit-list">
                  {aiExplanation.possible_actions.map((step, index) => (
                    <li key={`action-${index}`}>{step}</li>
                  ))}
                </ul>
              </>
            )}

          <p>
            <strong>Risk: </strong>
            {aiExplanation.risk}
          </p>

          {aiExplanation.confidence_note && (
            <p className="impact-note">
              {aiExplanation.confidence_note}
            </p>
          )}

          {Array.isArray(aiExplanation.limitations) &&
            aiExplanation.limitations.length > 0 && (
              <div className="ai-limitation">
                <span className="ai-limitation-label">limitation</span>
                <ul className="limit-list">
                  {aiExplanation.limitations.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              </div>
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

          {aiError && !aiLoading && (
            <p className="ai-regen-error">
              {aiError}
            </p>
          )}

        </div>

      ) : aiLoading ? (

        <div className="detail-empty">
          <span className="detail-empty-spinner" />
          Generating explanation&hellip;
          <small>
            {aiSlow ? (
              <>
                Still generating — the local model may be busy
                generating other explanations, so this can take
                several minutes. The result is saved as soon as it
                is ready — you can close this and reopen it to pick
                it up.
              </>
            ) : (
              <>
                Running on the local model — usually a minute or
                two, longer on the first request after a period of
                inactivity.
              </>
            )}
          </small>
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

    </div>
  )
}

function RecommendationView({
  recommendation,
  relatedFinding,
  impactRows,
  onViewFinding,
}) {
  return (
    <>

      {/* Recommended action */}

      <section className="detail-section recommendation-highlight">

        <SectionHeader
          eyebrow="/ Recommendation"
          title="Recommended implementation"
        />

        <div className="diag-reason">

          {recommendation.action ||
            recommendation.description ||
            'No implementation action was recorded.'}

        </div>

      </section>

      {/* Financial impact — right after the recommended action, since
          cost/savings/scope is the data reviewers look for first. */}

      {impactRows.length > 0 && (
        <section className="detail-section">

          <SectionHeader
            eyebrow="/ Financial impact"
            title="Estimated savings and scope"
          />

          <div className="detail-summary-grid">

            {impactRows.map(
              (row) => (
                <div
                  className={`detail-summary-card ${
                    row.big
                      ? 'detail-summary-card-big'
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

      {/* The validation/action plan is NOT rendered here as a
          hardcoded section: "What to verify" and "Possible actions"
          are generated by the local LLM and rendered inside the
          .ai-explanation block in the right-hand rail. */}

      {/* Rationale — only when there's real content beyond what the
          Recommended action / AI explanation sections already say. */}

      {(recommendation.reason ||
        recommendation.rationale ||
        recommendation.description) && (
        <section className="detail-section">

          <SectionHeader
            eyebrow="/ Rationale"
            title="Recommendation rationale"
          />

          <div className="diag-reason">

            {recommendation.reason ||
              recommendation.rationale ||
              recommendation.description}

          </div>

        </section>
      )}

      {/* Status */}

      <section className="detail-section">

        <SectionHeader
          eyebrow="/ Recommendation status"
          title="Current status"
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

  const [aiError, setAiError] =
    useState(null)

  const [aiSlow, setAiSlow] =
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
    setAiError(null)
    setAiSlow(false)

    if (
      !recommendationId ||
      cachedExplanation
    ) {
      return undefined
    }

    let cancelled = false

    setAiLoading(true)

    // After ~25s with no answer, switch the loading hint to a
    // "still generating" notice so the rail no longer reads as
    // frozen. Explanation generation can take several minutes when
    // the local model is already busy with the scan's background
    // prefetch, and the explanation is persisted server-side once
    // done -- closing and reopening the modal picks it up.
    const slowTimer = setTimeout(() => {
      if (!cancelled) {
        setAiSlow(true)
      }
    }, 25000)

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

        clearTimeout(slowTimer)

        if (!cancelled) {
          setAiLoading(false)
        }
      })

    return () => {
      cancelled = true
      clearTimeout(slowTimer)
    }

    // eslint-disable-next-line react-hooks/exhaustive-deps -- see above:
    // adding aiLoading/aiExplanation/recommendation.ai_explanation here
    // re-triggers this effect mid-flight and cancels the in-progress
    // request, which is the bug this keying exists to avoid.
  }, [recommendationId])

    function handleRegenerateExplanation() {

    if (!recommendationId) {
      return
    }

    // Keep the current explanation on screen while regeneration runs
    // instead of blanking it out. A slow or failed regeneration no
    // longer strands the user on the "Generating explanation…" state
    // with no content and no way back -- the previous explanation
    // stays visible, the button shows progress, and a failure is
    // surfaced inline below it.
    setAiLoading(true)
    setAiUnavailable(false)
    setAiError(null)
    setAiSlow(false)

    let regenCancelled = false

    const slowTimer = setTimeout(() => {
      if (!regenCancelled) {
        setAiSlow(true)
      }
    }, 25000)

    explainRecommendation(
      recommendationId,
      { force: true },
    )
      .then((result) => {

        setAiError(null)

        if (result?.ai_explanation) {
          setAiExplanation(
            result.ai_explanation,
          )
        } else {
          setAiUnavailable(true)
        }
      })
      .catch((err) => {

        // If there was already an explanation, keep it and report the
        // failure underneath. If there was none, fall back to the
        // "unavailable" empty state which carries its own Retry.
        if (aiExplanation) {
          setAiError(
            err?.message ||
              'Regeneration failed. The previous explanation is still shown.',
          )
        } else {
          setAiUnavailable(true)
        }
      })
      .finally(() => {
        regenCancelled = true
        clearTimeout(slowTimer)
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

  const scopeInfo = describeScope(
    recommendation?.scope,
    { region },
  )

  const severity =
    finding?.severity ||
    relatedFinding?.severity ||
    recommendation?.priority ||
    recommendation?.severity ||
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
                  scopeInfo && (
                    <span title={scopeInfo.full}>
                      {scopeInfo.label}:{' '}
                      <span className="mono">
                        {scopeInfo.value}
                      </span>
                    </span>
                  )}

              </div>

            </div>

          </div>
        </div>

        {/* Body */}

        {isFindingMode && (
          <div className="modal-body">
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
          </div>
        )}

        {isRecommendationMode && (
          <div className="modal-body">

            <div className="modal-body-main">
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
              />
            </div>

            <div className="modal-body-rail">

              <div className="rail-head">
                <div className="rail-brand">
                  <div className="rail-brand-mark">AI</div>
                  <strong>Explanation</strong>
                  <span className="rail-local-tag">
                    Local model
                  </span>
                </div>
              </div>

              <div className="rail-scroll">
                <AIExplanationRail
                  aiExplanation={
                    aiExplanation
                  }
                  aiLoading={
                    aiLoading
                  }
                  aiUnavailable={
                    aiUnavailable
                  }
                  aiSlow={
                    aiSlow
                  }
                  aiError={
                    aiError
                  }
                  onRegenerateExplanation={
                    handleRegenerateExplanation
                  }
                />
              </div>

            </div>

          </div>
        )}

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