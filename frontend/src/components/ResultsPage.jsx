import { useMemo, useState } from 'react'

import {
  formatMoneyOrDash,
  pluralize,
  sevClass,
  sevLabel,
  truncateId,
} from '../utils/format'

import { serviceStyle } from '../utils/serviceStyle'

import {
  RECONCILIATION_TYPES,
  attributionInfo,
} from '../mappers/findings'

import UnifiedFindingRecommendationModal from './UnifiedFindingRecommendationModal'
import CollectionSummaryModal from './CollectionSummaryModal'
import CostDriverList from './CostDriverList'

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
    ? truncateId(
        id,
        28,
      )
    : 'No resource identified'
}

function recommendationTitle(
  recommendation,
) {
  return (
    recommendation?.title ||
    recommendation?.name ||
    recommendation?.recommendation ||
    'Optimization recommendation'
  )
}

function recommendationReason(
  recommendation,
) {
  return (
    recommendation?.reason ||
    recommendation?.rationale ||
    recommendation?.description ||
    'No recommendation rationale was recorded.'
  )
}

function recommendationId(
  recommendation,
) {
  return (
    recommendation?.id ||
    recommendation?.recommendation_id ||
    recommendation?.recommendation_key ||
    null
  )
}

function findingId(finding) {
  return (
    finding?.id ||
    finding?.finding_id ||
    null
  )
}

function normalizeFindingKey(
  finding,
) {
  return String(
    findingId(finding) ??
      finding?.finding_key ??
      finding?.finding_type ??
      finding?.key ??
      finding?.fullTitle ??
      '',
  )
}

/*
 * Resolve the source finding without opening it.
 *
 * This function is intentionally separate from modal state.
 * A recommendation may reference a finding, but that does
 * not mean the finding modal should also be opened.
 */
function findRelatedFinding(
  recommendation,
  findingList,
) {
  if (!recommendation) {
    return null
  }

  /*
   * 1. Direct finding ID.
   */
  const explicitIds = [
    recommendation.finding_id,
    recommendation.findingId,
    recommendation.related_finding_id,
  ].filter(
    (value) =>
      value !== null &&
      value !== undefined &&
      value !== '',
  )

  for (const explicitId of explicitIds) {
    const match = findingList.find(
      (finding) =>
        String(
          findingId(finding),
        ) === String(explicitId),
    )

    if (match) {
      return match
    }
  }

  /*
   * 2. Explicit embedded finding.
   */
  if (
    recommendation.finding &&
    typeof recommendation.finding ===
      'object'
  ) {
    return recommendation.finding
  }

  /*
   * 3. Recommendation may carry source finding IDs.
   */
  const sourceFindingIds = Array.isArray(
    recommendation.source_finding_ids,
  )
    ? recommendation.source_finding_ids
    : []

  for (const sourceId of sourceFindingIds) {
    const match = findingList.find(
      (finding) =>
        String(
          findingId(finding),
        ) === String(sourceId),
    )

    if (match) {
      return match
    }
  }

  /*
   * 4. Resource identity.
   */
  const affectedResources =
    Array.isArray(
      recommendation.affected_resources,
    )
      ? recommendation.affected_resources
      : []

  if (
    recommendation.resource_id ||
    recommendation.resourceId ||
    affectedResources.length
  ) {
    const resourceCandidates = [
      recommendation.resource_id,
      recommendation.resourceId,
      ...affectedResources,
    ].filter(Boolean)

    const match = findingList.find(
      (finding) => {
        const findingResources = [
          ...(finding.resourceIds || []),
          ...(finding.resource_ids || []),
          finding.resource,
          finding.resource_id,
        ].filter(Boolean)

        return resourceCandidates.some(
          (candidate) =>
            findingResources.includes(
              candidate,
            ),
        )
      },
    )

    if (match) {
      return match
    }
  }

  /*
   * 5. Service + region fallback.
   */
  const recommendationService =
    recommendation.service ||
    recommendation.resource_type

  const recommendationRegion =
    recommendation.region ||
    null

  if (
    recommendationService ||
    recommendationRegion
  ) {
    const serviceMatch =
      String(
        recommendationService || '',
      ).toLowerCase()

    const regionMatch =
      String(
        recommendationRegion || '',
      ).toLowerCase()

    return (
      findingList.find(
        (finding) => {
          const findingService =
            String(
              finding.service ||
                finding.resource_type ||
                '',
            ).toLowerCase()

          const findingRegion =
            String(
              finding.region || '',
            ).toLowerCase()

          const serviceOk =
            !serviceMatch ||
            findingService ===
              serviceMatch

          const regionOk =
            !regionMatch ||
            !findingRegion ||
            findingRegion ===
              regionMatch

          return serviceOk && regionOk
        },
      ) || null
    )
  }

  return null
}


const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

function findingTitle(finding) {
  return (
    finding.fullTitle ||
    finding.title ||
    'Optimization finding'
  )
}

function findingService(finding) {
  return (
    finding.service ||
    finding.resource_type ||
    'AWS service'
  )
}

const SCOPE_TONE_COLORS = {
  good: { bg: 'rgba(34,197,94,0.15)', fg: '#15803d' },
  neutral: { bg: 'rgba(148,163,184,0.2)', fg: '#475569' },
}

function CostScopeTag({ scope }) {
  if (!scope) {
    return null
  }

  const info = attributionInfo(scope)
  const colors =
    SCOPE_TONE_COLORS[info.tone] ||
    SCOPE_TONE_COLORS.neutral

  return (
    <span
      title={info.tooltip}
      style={{
        display: 'inline-block',
        marginTop: 4,
        padding: '1px 7px',
        borderRadius: 999,
        fontSize: '0.7em',
        fontWeight: 600,
        whiteSpace: 'nowrap',
        background: colors.bg,
        color: colors.fg,
      }}
    >
      {info.label}
    </span>
  )
}

function FindingHeroCard({ finding, onClick }) {
  return (
    <button
      type="button"
      className="finding-hero"
      onClick={onClick}
    >
      <div>
        <span
          className={`sev-badge on-dark ${sevClass(
            finding.severity,
          )}`}
        >
          {sevLabel(finding.severity)}
        </span>

        <h3>{findingTitle(finding)}</h3>

        <div className="fh-meta">
          {findingService(finding)}
        </div>

        <div className="fh-resource">
          {resourceLabel(finding)}
        </div>
      </div>

      <div>
        <div className="fh-saving mono">
          {finding.costLabel ||
            formatMoneyOrDash(finding.cost)}
        </div>

        <CostScopeTag scope={finding.costScope} />

        <div className="fh-link">
          View details <span>→</span>
        </div>
      </div>
    </button>
  )
}

function FindingCard({ finding, onClick }) {
  const style = serviceStyle(findingService(finding))

  return (
    <button
      type="button"
      className="finding-card"
      onClick={onClick}
    >
      <div>
        <div className="fc-top">
          <div
            className="fc-ico"
            style={{ background: style.color }}
          >
            {style.icon}
          </div>

          <span
            className={`sev-badge ${sevClass(
              finding.severity,
            )}`}
          >
            {sevLabel(finding.severity)}
          </span>
        </div>

        <h4>{findingService(finding)}</h4>

        <div className="fc-resource">
          {resourceLabel(finding)}
        </div>

        <div className="fc-issue">
          {findingTitle(finding)}
        </div>
      </div>

      <div className="fc-foot">
        <div>
          <span className="fc-saving mono">
            {finding.costLabel ||
              formatMoneyOrDash(finding.cost)}
          </span>

          <CostScopeTag scope={finding.costScope} />
        </div>

        <span className="fc-arrow">→</span>
      </div>
    </button>
  )
}


function RecommendationRow({
  recommendation,
  relatedFinding,
  onClick,
}) {
  const priority =
    recommendation?.priority ||
    recommendation?.severity ||
    'medium'

  const affectedResources =
    recommendation
      ?.affectedResourceCount ??
    recommendation
      ?.affected_resource_count ??
    (
      Array.isArray(
        recommendation?.affected_resources,
      )
        ? recommendation
            .affected_resources
            .length
        : 1
    )

  const resourceIdList =
    Array.isArray(
      recommendation?.affectedResources,
    )
      ? recommendation.affectedResources
      : Array.isArray(
            recommendation?.affected_resources,
          )
        ? recommendation.affected_resources
        : []

  // One recommendation per finding is the norm now, so several rows
  // can share an identical title/reason (e.g. 3 separate idle NAT
  // gateways) -- show the specific resource ID so they don't read
  // as accidental duplicates.
  const resourceIdLabel =
    Number(affectedResources) === 1 &&
    resourceIdList[0]
      ? truncateId(
          String(resourceIdList[0]),
          24,
        )
      : null

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

          {resourceIdLabel && (
            <span className="recommendation-resource-id mono">
              {' '}
              · {resourceIdLabel}
            </span>
          )}
        </div>

        <div className="recommendation-meta">
          {affectedResources}{' '}
          {Number(
            affectedResources,
          ) === 1
            ? 'resource'
            : 'resources'}{' '}
          affected
        </div>

        <div className="recommendation-reason">
          {recommendationReason(
            recommendation,
          )}
        </div>

        {relatedFinding && (
          <div className="recommendation-related">
            Source finding:{' '}
            {relatedFinding.fullTitle ||
              relatedFinding.title ||
              'Optimization finding'}
          </div>
        )}
      </div>

      <div className="recommendation-priority">
        <span
          className={`sev-badge ${sevClass(
            priority,
          )}`}
        >
          {sevLabel(priority)}
        </span>
      </div>
    </button>
  )
}


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


export default function ResultsPage({
  scanId,
  scan: resultsScan,
  findings = {},
  recommendations = [],
  costSummary = null,
  costDrivers = [],
  collectionSummary = null,
  collectionSummaryLoading = false,
  collectionSummaryError = null,
  onLoadCollectionSummary,
  hasResults = false,
  loading = false,
  error = null,
  onRefresh,
  onBack,
  onRunAnalysis,
}) {
  const [
    selectedFinding,
    setSelectedFinding,
  ] = useState(null)

  const [
    selectedRecommendation,
    setSelectedRecommendation,
  ] = useState(null)

  const [
    collectionSummaryOpen,
    setCollectionSummaryOpen,
  ] = useState(false)

  function openCollectionSummary() {
    setCollectionSummaryOpen(true)
    onLoadCollectionSummary?.(scanId)
  }

  const findingList = useMemo(
    () =>
      Object.values(
        findings || {},
      ),
    [findings],
  )

  const recommendationList =
    Array.isArray(
      recommendations,
    )
      ? recommendations
      : []

  const reconciliationFindings =
    findingList.filter(
      (finding) =>
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

  const rankedFindings =
    optimizationFindings
      .slice()
      .sort((a, b) => {
        const rankDiff =
          (SEVERITY_RANK[String(b.severity || '').toLowerCase()] || 0) -
          (SEVERITY_RANK[String(a.severity || '').toLowerCase()] || 0)

        if (rankDiff !== 0) return rankDiff

        return Number(b?.cost || 0) - Number(a?.cost || 0)
      })

  /*
   * IMPORTANT:
   *
   * A finding click MUST open a finding only.
   * The linked recommendation is merely available
   * through "View recommendation" inside the modal.
   */
  function openFinding(finding) {
    setSelectedRecommendation(null)
    setSelectedFinding(finding)
  }

  /*
   * A recommendation click MUST open a recommendation only.
   * The related finding is passed separately so the modal
   * can display a "Source finding" link.
   */
  function openRecommendation(
    recommendation,
  ) {
    setSelectedFinding(null)
    setSelectedRecommendation(
      recommendation,
    )
  }

  function closeModal() {
    setSelectedFinding(null)
    setSelectedRecommendation(null)
  }

  /*
   * Open the source finding from a recommendation.
   */
  function openSourceFinding(
    finding,
  ) {
    if (!finding) {
      return
    }

    setSelectedRecommendation(null)
    setSelectedFinding(finding)
  }

  /*
   * Open the recommendation associated with
   * the currently displayed finding.
   */
  function openRecommendationFromFinding(
    finding,
  ) {
    if (!finding) {
      return
    }

    const findingIdentifier =
      findingId(finding)

    const linked =
      recommendationList.find(
        (recommendation) => {
          const recommendationFindingIds =
            [
              recommendation.finding_id,
              recommendation.findingId,
              recommendation.related_finding_id,
              ...(Array.isArray(
                recommendation.source_finding_ids,
              )
                ? recommendation.source_finding_ids
                : []),
            ].filter(
              (value) =>
                value !== null &&
                value !== undefined,
            )

          if (
            findingIdentifier != null
          ) {
            const directMatch =
              recommendationFindingIds.some(
                (value) =>
                  String(value) ===
                  String(
                    findingIdentifier,
                  ),
              )

            if (directMatch) {
              return true
            }
          }

          const findingResources = [
            ...(finding.resourceIds ||
              []),
            ...(finding.resource_ids ||
              []),
            finding.resource,
            finding.resource_id,
          ].filter(Boolean)

          const recommendationResources =
            [
              recommendation.resource_id,
              recommendation.resourceId,
              ...(Array.isArray(
                recommendation.affected_resources,
              )
                ? recommendation.affected_resources
                : []),
            ].filter(Boolean)

          if (
            findingResources.length &&
            recommendationResources.some(
              (resource) =>
                findingResources.includes(
                  resource,
                ),
            )
          ) {
            return true
          }

          const findingService =
            String(
              finding.service ||
                finding.resource_type ||
                '',
            ).toLowerCase()

          const recommendationService =
            String(
              recommendation.service ||
                recommendation.resource_type ||
                '',
            ).toLowerCase()

          const findingRegion =
            String(
              finding.region || '',
            ).toLowerCase()

          const recommendationRegion =
            String(
              recommendation.region || '',
            ).toLowerCase()

          return (
            findingService &&
            recommendationService &&
            findingService ===
              recommendationService &&
            (
              !recommendationRegion ||
              !findingRegion ||
              findingRegion ===
                recommendationRegion
            )
          )
        },
      )

    /*
     * Do not open an empty recommendation modal.
     */
    if (!linked) {
      return
    }

    setSelectedFinding(null)
    setSelectedRecommendation(
      linked,
    )
  }

  const scanNumber =
    resultsScan?.id ??
    resultsScan?.scan_id ??
    scanId

  const totalFindingCost =
    findingList.reduce(
      (sum, finding) =>
        sum +
        Number(
          finding?.cost || 0,
        ),
      0,
    )

  const totalMonthlySavings =
    recommendationList.reduce(
      (sum, recommendation) =>
        sum +
        Number(
          recommendation
            ?.financial_impact
            ?.estimated_monthly_savings ??
            recommendation?.estimated_monthly_savings ??
            0,
        ),
      0,
    )

  return (
    <div className="results-page">

      <div className="header-row">
        <div className="headline">

          <h1>
            Optimization Insights
          </h1>

          <div className="sub">
            Review detected cost conditions,
            recommended optimization actions,
            supporting evidence, and affected
            AWS resources.
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

          {hasResults && (
            <button
              type="button"
              className="small-btn"
              onClick={openCollectionSummary}
            >
              View Collection Summary
            </button>
          )}

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
              No optimization results
            </h3>

            <p>
              Run an analysis to identify
              cost conditions and
              optimization opportunities.
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
                      '—'}
                    {' → '}
                    {resultsScan.end_date ||
                      '—'}
                    {' · '}
                    {resultsScan.region ||
                      'All regions'}
                  </div>

                </div>

                <button
                  type="button"
                  className="small-btn"
                  onClick={() =>
                    onRefresh?.(
                      scanNumber,
                    )
                  }
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
                    Analysis-period spend
                  </span>

                  <span className="stat-v mono">
                    {formatMoneyOrDash(costSummary?.total_cost,)}
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
                    Recommended actions
                  </span>

                  <span className="stat-v mono">
                    {
                      recommendationList.length
                    }
                  </span>
                </div>

                <div
                  className="stat-chip"
                  title="Sum of estimated savings across recommendations where cost is confirmed as the affected resource's own cost. Shared or unconfirmed billing evidence is excluded."
                >
                  <span className="stat-k">
                    Potential monthly savings (confirmed)
                  </span>

                  <span className="stat-v mono">
                    {formatMoneyOrDash(
                      totalMonthlySavings,
                    )}
                  </span>
                </div>

              </div>

            </section>

            <section className="panel cost-drivers-panel section-gap">

              <div className="panel-head">

                <div>

                  <div className="eyebrow">
                    / Cost Drivers
                  </div>

                  <div className="panel-title">
                    Where the spend is concentrated
                  </div>

                </div>

                <span className="snapshot-count">
                  {pluralize(
                    costDrivers.length,
                    'service',
                  )}
                </span>

              </div>

              <CostDriverList drivers={costDrivers} />

            </section>

            <section className="panel section-gap">

              <div className="panel-head">

                <div>

                  <div className="eyebrow">
                    / What Needs Attention
                  </div>

                  <div className="panel-title">
                    Optimization findings
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
                <div className="findings-bento">

                  <FindingHeroCard
                    finding={rankedFindings[0]}
                    onClick={() =>
                      openFinding(rankedFindings[0])
                    }
                  />

                  {rankedFindings.length > 1 && (
                    <div className="findings-card-grid">
                      {rankedFindings.slice(1).map(
                        (finding) => (
                          <FindingCard
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

                </div>
              )}

            </section>

            <section className="panel section-gap recommendations-results-panel">

              <div className="panel-head">

                <div>

                  <div className="eyebrow">
                    / What To Do Next
                  </div>

                  <div className="panel-title">
                    Recommended actions
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
                  generated for this scan.
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
                            ) ||
                            index
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

            <section className="panel section-gap data-quality-panel">

              <div className="panel-head">

                <div>

                  <div className="eyebrow">
                    / Data Quality
                  </div>

                  <div className="panel-title">
                    Billing & resource checks
                  </div>

                </div>

                <span className="snapshot-count">
                  {
                    reconciliationFindings.length
                  }{' '}
                  {
                    reconciliationFindings.length ===
                    1
                      ? 'check'
                      : 'checks'
                  }
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
        onViewFinding={
          openSourceFinding
        }
        onViewRecommendation={
          openRecommendationFromFinding
        }
      />

      <CollectionSummaryModal
        open={collectionSummaryOpen}
        loading={collectionSummaryLoading}
        error={collectionSummaryError}
        summary={collectionSummary}
        onClose={() => setCollectionSummaryOpen(false)}
      />

    </div>
  )
}