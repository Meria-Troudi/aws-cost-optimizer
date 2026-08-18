import { useMemo, useState } from 'react'
import {
  formatDate,
  formatMoneyOrDash,
  sevLabel,
  truncateId,
} from '../utils/format'
import { serviceStyle } from '../utils/serviceStyle'
import UnifiedFindingRecommendationModal from './UnifiedFindingRecommendationModal'

const RECONCILIATION_TYPES = [
  'historical_unmatched',
  'historical_spend_no_current_resource',
  'historical_resource_not_found',
  'collection_no_matching_resources',
  'billing_resource_mismatch',
  'billing_no_cost',
  'billing_reconciliation_unknown',
]

function severityClass(severity) {
  const value = String(severity || 'low').toLowerCase()

  if (value === 'critical') return 'sev-critical'
  if (value === 'high') return 'sev-high'
  if (value === 'medium') return 'sev-medium'

  return 'sev-low'
}

function resourceLabel(finding) {
  const count =
    finding?.resourceCount ??
    finding?.resource_count

  if (Number(count) > 1) {
    return `${count} resources`
  }

  const id =
    finding?.resourceIds?.[0] ||
    finding?.resource_ids?.[0] ||
    finding?.resource ||
    finding?.resource_id

  return id
    ? truncateId(id, 28)
    : 'No resource identified'
}

function recommendationTitle(recommendation) {
  return (
    recommendation?.title ||
    recommendation?.name ||
    recommendation?.recommendation ||
    'Optimization recommendation'
  )
}

function recommendationReason(recommendation) {
  return (
    recommendation?.rationale ||
    recommendation?.reason ||
    recommendation?.description ||
    'Review this recommendation and its supporting evidence.'
  )
}

function recommendationId(recommendation) {
  return (
    recommendation?.id ||
    recommendation?.recommendation_id ||
    recommendation?.finding_id ||
    null
  )
}

function findingId(finding) {
  return finding?.id || finding?.finding_id || null
}

function normalizeFindingKey(finding) {
  return String(
    findingId(finding) ??
      finding?.key ??
      finding?.fullTitle ??
      '',
  )
}

function findRelatedFinding(
  recommendation,
  findingList,
) {
  if (!recommendation) return null

  const explicitId =
    recommendation.finding_id ||
    recommendation.findingId ||
    recommendation.related_finding_id

  if (explicitId != null) {
    const match = findingList.find(
      (finding) =>
        String(findingId(finding)) ===
        String(explicitId),
    )

    if (match) return match
  }

  const explicitFinding =
    recommendation.finding

  if (
    explicitFinding &&
    typeof explicitFinding === 'object'
  ) {
    return explicitFinding
  }

  const resourceId =
    recommendation.resource_id ||
    recommendation.resourceId

  if (resourceId) {
    const match = findingList.find(
      (finding) =>
        finding.resourceIds?.includes(
          resourceId,
        ) ||
        finding.resource_ids?.includes(
          resourceId,
        ) ||
        finding.resource === resourceId ||
        finding.resource_id === resourceId,
    )

    if (match) return match
  }

  const service = recommendation.service
  const region = recommendation.region

  if (service || region) {
    return (
      findingList.find((finding) => {
        const serviceMatches =
          !service ||
          String(
            finding.service || '',
          ).toLowerCase() ===
            String(service).toLowerCase()

        const regionMatches =
          !region ||
          !finding.region ||
          String(
            finding.region,
          ).toLowerCase() ===
            String(region).toLowerCase()

        return (
          serviceMatches &&
          regionMatches
        )
      }) || null
    )
  }

  return null
}

/* -------------------------------------------------------------------------- */
/* Finding row                                                                */
/* -------------------------------------------------------------------------- */

function FindingRow({
  finding,
  onClick,
}) {
  const style = serviceStyle(
    finding.service,
  )

  return (
    <button
      type="button"
      className="finding-result-row"
      onClick={onClick}
    >
      <div
        className="fnd-ico"
        style={{
          background: style.color,
        }}
      >
        {style.icon}
      </div>

      <div className="finding-result-main">
        <div className="fnd-service-name">
          {finding.service || 'AWS service'}
        </div>

        <div className="fnd-issue">
          {finding.fullTitle ||
            finding.title ||
            'Optimization finding'}
        </div>

        <div className="fnd-resource">
          {resourceLabel(finding)}
        </div>
      </div>

      <span
        className={`sev-badge ${severityClass(
          finding.severity,
        )}`}
      >
        {sevLabel(finding.severity)}
      </span>

      <div className="fnd-saving">
        {finding.costLabel ||
          formatMoneyOrDash(
            finding.cost,
          )}
      </div>

  
    </button>
  )
}

/* -------------------------------------------------------------------------- */
/* Recommendation row                                                         */
/* -------------------------------------------------------------------------- */

function RecommendationRow({
  recommendation,
  relatedFinding,
  onClick,
}) {
  const priority =
    recommendation.priority ||
    recommendation.severity ||
    'medium'

  const affectedResources =
    recommendation.affectedResourceCount ??
    recommendation.affected_resource_count ??
    1

  return (
    <button
      type="button"
      className="recommendation-row recommendation-row-button"
      onClick={onClick}
    >
      <div className="recommendation-main">
        <div className="recommendation-title">
          {recommendationTitle(
            recommendation,
          )}
        </div>

        <div className="recommendation-meta">
          {recommendation.meta ||
            `${affectedResources} ${
              affectedResources === 1
                ? 'resource'
                : 'resources'
            } affected`}
        </div>

        <div className="recommendation-reason">
          {recommendationReason(
            recommendation,
          )}
        </div>

        {relatedFinding && (
          <div className="recommendation-related">
            Based on:{' '}
            {relatedFinding.fullTitle ||
              relatedFinding.title}
          </div>
        )}
      </div>

      <div className="recommendation-priority">
        <span
          className={`sev-badge ${severityClass(
            priority,
          )}`}
        >
          {sevLabel(priority)}
        </span>
      </div>

      
    </button>
  )
}

/* -------------------------------------------------------------------------- */
/* Reconciliation row                                                         */
/* -------------------------------------------------------------------------- */

function ReconciliationRow({
  finding,
  onClick,
}) {
  return (
    <button
      type="button"
      className="reconciliation-row reconciliation-row-button"
      onClick={onClick}
    >
      <div>
        <strong>
          {finding.fullTitle ||
            finding.title ||
            'Billing or data-quality issue'}
        </strong>

        <span>
          {finding.region ||
            'All regions'}
        </span>
      </div>

      <span>
        {finding.costLabel ||
          formatMoneyOrDash(
            finding.cost,
          )}
      </span>

     
    </button>
  )
}

/* -------------------------------------------------------------------------- */
/* Page                                                                       */
/* -------------------------------------------------------------------------- */

export default function ResultsPage({
  scanId,
  scan: resultsScan,
  findings = {},
  recommendations = [],
  costSummary = null,
  loading = false,
  error = null,
  onRefresh,
  onBack,
  onRunAnalysis,
}) {
  const hasResults = Boolean(resultsScan && [
    'completed',
    'completed_with_errors',
  ].includes(String(resultsScan.status || '').toLowerCase()))

  const [
    selectedFinding,
    setSelectedFinding,
  ] = useState(null)

  const [
    selectedRecommendation,
    setSelectedRecommendation,
  ] = useState(null)

  const findingList = useMemo(
    () => Object.values(findings || {}),
    [findings],
  )

  const recommendationList =
    Array.isArray(recommendations)
      ? recommendations
      : []

  const scanRegion =
    resultsScan?.region ||
    'All regions'

  const reconciliationFindings =
    findingList.filter((finding) =>
      RECONCILIATION_TYPES.includes(
        finding.findingType ||
          finding.finding_type,
      ),
    )

  const optimizationFindings =
    findingList.filter(
      (finding) =>
        !RECONCILIATION_TYPES.includes(
          finding.findingType ||
            finding.finding_type,
        ),
    )

  function openFinding(finding) {
    // Find a recommendation linked to this finding
    const linkedRec = recommendationList.find(
      (rec) => {
        const recFindingId =
          rec.finding_id ||
          rec.findingId ||
          rec.related_finding_id
        const findingIdV = findingId(finding)

        if (
          recFindingId != null &&
          findingIdV != null
        ) {
          return (
            String(recFindingId) ===
            String(findingIdV)
          )
        }

        return (
          !rec.service ||
          !finding.service ||
          String(rec.service).toLowerCase() ===
            String(finding.service).toLowerCase()
        ) &&
        (
          !rec.region ||
          !finding.region ||
          String(rec.region).toLowerCase() ===
            String(finding.region).toLowerCase()
        )
      },
    )

    setSelectedRecommendation(
      linkedRec || null,
    )
    setSelectedFinding(finding)
  }

  function openRecommendation(
    recommendation,
  ) {
    const related =
      findRelatedFinding(
        recommendation,
        findingList,
      )

    setSelectedFinding(related)
    setSelectedRecommendation(
      recommendation,
    )
  }

  function closeModal() {
    setSelectedFinding(null)
    setSelectedRecommendation(null)
  }

  function focusFinding(finding) {
    if (!finding) return

    setSelectedFinding(finding)
  }

  function openRecommendationFromFinding(finding) {
    if (!finding) return

    // Try to find a recommendation linked to this finding
    const linked = recommendationList.find(
      (rec) => {
        const recFindingId =
          rec.finding_id ||
          rec.findingId
        if (
          recFindingId != null &&
          findingId(finding) != null
        ) {
          return (
            String(recFindingId) ===
            String(findingId(finding))
          )
        }

        return (
          (!rec.service ||
            !finding.service ||
            String(rec.service).toLowerCase() ===
              String(finding.service).toLowerCase()) &&
          (!rec.region ||
            !finding.region ||
            String(rec.region).toLowerCase() ===
              String(finding.region).toLowerCase())
        )
      },
    )

    if (linked) {
      setSelectedRecommendation(linked)
    }

    setSelectedFinding(finding)
  }

  const scanNumber =
    resultsScan?.id ??
    resultsScan?.scan_id

  /*
   * Cost summary
   */
  const totalFindingCost = findingList.reduce(
    (sum, finding) =>
      sum + Number(finding.cost || 0),
    0,
  )

  const totalMonthlySavings =
    recommendationList.reduce(
      (sum, rec) =>
        sum +
        Number(
          rec.estimated_monthly_savings ??
            rec.estimatedMonthlySavings ??
            rec.monthly_savings ??
            0,
        ),
      0,
    )

  const totalAnnualSavings =
    recommendationList.reduce(
      (sum, rec) =>
        sum +
        Number(
          rec.estimated_annual_savings ??
            rec.estimatedAnnualSavings ??
            rec.annual_savings ??
            0,
        ),
      0,
    )

  return (
    <div className="results-page">

      {/* ------------------------------------------------------------------ */}
      {/* Header                                                             */}
      {/* ------------------------------------------------------------------ */}

      <div className="header-row">
        <div className="headline">
          <h1>Optimization Insights</h1>

          <div className="sub">
            Review what is driving AWS cost,
            where action is recommended, and
            which resources need attention.
          </div>
        </div>

        <div className="dashboard-actions">
          <button
            type="button"
            className="small-btn"
            onClick={onBack}
          >
            ← Back to overview
          </button>

          <button
            type="button"
            className="small-btn primary-btn"
            onClick={onRunAnalysis}
          >
            Run New Analysis
          </button>
        </div>
      </div>

      {error && (
        <div className="page-error section-gap">
          {error}
        </div>
      )}

      {loading && (
        <div className="page-loading">
          Loading optimization insights…
        </div>
      )}

      {!loading &&
        !hasResults &&
        !error && (
          <div className="empty-state section-gap">
            <div className="empty-ico">
              ◎
            </div>

            <h3>
              No optimization results yet
            </h3>

            <p>
              Run an analysis to identify
              cost-saving opportunities and
              resources that need attention.
            </p>

            <button
              type="button"
              className="small-btn primary-btn"
              onClick={onRunAnalysis}
            >
              Run Optimization Analysis
            </button>
          </div>
        )}

      {hasResults &&
        resultsScan && (
          <>
            {/* ------------------------------------------------------------ */}
            {/* Scan summary                                                  */}
            {/* ------------------------------------------------------------ */}

            <section className="panel section-gap results-summary-panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">
                    / Analysis Summary
                  </div>

                  <div className="panel-title">
                    Scan #{scanNumber}
                  </div>

                  <div className="panel-sub">
                    {resultsScan.start_date ||
                      '—'}{' '}
                    {' '}
                    {resultsScan.end_date ||
                      '—'}
                    {' · '}
                    {scanRegion}
                  </div>
                </div>

                <button
                  type="button"
                  className="small-btn"
                  onClick={() => onRefresh?.(scanNumber)}
                >
                  Refresh Results
                </button>
              </div>

              <div className="stats-row">
                <div className="stat-chip">
                  <span className="stat-k">
                    Scan status
                  </span>

                  <span className="stat-v">
                    {resultsScan.status ||
                      '—'}
                  </span>
                </div>

                <div className="stat-chip">
                  <span className="stat-k">
                    Optimization findings
                  </span>

                  <span className="stat-v mono">
                    {
                      optimizationFindings.length
                    }
                  </span>
                </div>

                <div className="stat-chip">
                  <span className="stat-k">
                    Analysis-period spend
                  </span>

                  <span className="stat-v mono">
                    {formatMoneyOrDash(costSummary?.total_cost)}
                  </span>
                </div>

                <div className="stat-chip">
                  <span className="stat-k">
                    Recommended actions
                  </span>

                  <span className="stat-v mono">
                    {
                      recommendationList.length
                    }
                  </span>
                </div>

                <div className="stat-chip">
                  <span className="stat-k">
                    Implied monthly impact
                  </span>

                  <span className="stat-v mono">
                    {totalMonthlySavings > 0
                      ? formatMoneyOrDash(
                          totalMonthlySavings,
                        )
                      : '—'}
                  </span>
                </div>

                <div className="stat-chip">
                  <span className="stat-k">
                    Implied annual impact
                  </span>

                  <span className="stat-v mono">
                    {totalAnnualSavings > 0
                      ? formatMoneyOrDash(
                          totalAnnualSavings,
                        )
                      : '—'}
                  </span>
                </div>
              </div>
            </section>

            {/* ------------------------------------------------------------ */}
            {/* Findings                                                       */}
            {/* ------------------------------------------------------------ */}

            <section className="panel section-gap">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">
                    / What Needs Attention
                  </div>

                  <div className="panel-title">
                    Optimization Findings
                  </div>

                  <div className="panel-sub">
                    Cost conditions detected in
                    your AWS environment. Open a
                    finding to review the affected
                    resource and supporting evidence.
                  </div>
                </div>

                <span className="snapshot-count">
                  {optimizationFindings.length}{' '}
                  {optimizationFindings.length ===
                  1
                    ? 'finding'
                    : 'findings'}
                </span>
              </div>

              {!optimizationFindings.length ? (
                <div className="chart-empty">
                  No optimization issues were
                  identified in this analysis.
                </div>
              ) : (
                <div className="findings-results-list">
                  {optimizationFindings.map(
                    (finding) => (
                      <FindingRow
                        key={normalizeFindingKey(
                          finding,
                        )}
                        finding={finding}
                        onClick={() =>
                          openFinding(
                            finding,
                          )
                        }
                      />
                    ),
                  )}
                </div>
              )}
            </section>

            {/* ------------------------------------------------------------ */}
            {/* Recommendations                                               */}
            {/* ------------------------------------------------------------ */}

            <section className="panel section-gap recommendations-results-panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">
                    / What To Do Next
                  </div>

                  <div className="panel-title">
                    Recommended Actions
                  </div>

                  <div className="panel-sub">
                    Practical actions generated
                    from the findings and their
                    supporting evidence.
                  </div>
                </div>

                <span className="snapshot-count">
                  {recommendationList.length}{' '}
                  {recommendationList.length ===
                  1
                    ? 'action'
                    : 'actions'}
                </span>
              </div>

              {!recommendationList.length ? (
                <div className="chart-empty">
                  No optimization actions were
                  recommended for this scan.
                </div>
              ) : (
                <div className="recommendations-list">
                  {recommendationList.map(
                    (
                      recommendation,
                      index,
                    ) => {
                      const related =
                        findRelatedFinding(
                          recommendation,
                          findingList,
                        )

                      return (
                        <RecommendationRow
                          key={
                            recommendationId(
                              recommendation,
                            ) || index
                          }
                          recommendation={
                            recommendation
                          }
                          relatedFinding={
                            related
                          }
                          onClick={() =>
                            openRecommendation(
                              recommendation,
                            )
                          }
                        />
                      )
                    },
                  )}
                </div>
              )}
            </section>

            {/* ------------------------------------------------------------ */}
            {/* Data quality                                                   */}
            {/* ------------------------------------------------------------ */}

            <section className="panel section-gap data-quality-panel">
              <div className="panel-head">
                <div>
                  <div className="eyebrow">
                    / Data Quality
                  </div>

                  <div className="panel-title">
                    Billing & Resource Checks
                  </div>

                  <div className="panel-sub">
                    Items that may affect cost
                    attribution or resource
                    reconciliation. These are
                    separate from optimization
                    opportunities.
                  </div>
                </div>

                <span className="snapshot-count">
                  {reconciliationFindings.length}{' '}
                  {reconciliationFindings.length ===
                  1
                    ? 'check'
                    : 'checks'}
                </span>
              </div>

              {!reconciliationFindings.length ? (
                <div className="chart-empty">
                  No billing or resource
                  reconciliation issues were
                  detected.
                </div>
              ) : (
                <div className="reconciliation-list">
                  {reconciliationFindings.map(
                    (finding) => (
                      <ReconciliationRow
                        key={normalizeFindingKey(
                          finding,
                        )}
                        finding={finding}
                        onClick={() =>
                          openFinding(
                            finding,
                          )
                        }
                      />
                    ),
                  )}
                </div>
              )}
            </section>
          </>
        )}

      <UnifiedFindingRecommendationModal
        finding={selectedFinding}
        recommendation={
          selectedRecommendation
        }
        relatedFinding={
          selectedRecommendation
            ? findRelatedFinding(
                selectedRecommendation,
                findingList,
              )
            : null
        }
        onClose={closeModal}
        onViewFinding={focusFinding}
        onViewRecommendation={
          openRecommendationFromFinding
        }
      />
    </div>
  )
}
