import { useEffect, useMemo, useState } from 'react'

import {
  formatDate,
  formatMoneyOrDash,
  formatPct,
  pluralize,
  sevClass,
  sevLabel,
  truncateId,
} from '../utils/format'

import { serviceStyle } from '../utils/serviceStyle'

import {
  isDoneStatus,
  isFailedStatus,
  isRunningStatus,
} from '../utils/scanStatus'

import {
  RECONCILIATION_TYPES,
  attributionInfo,
  resolveReconciliationService,
} from '../mappers/findings'

import UnifiedFindingRecommendationModal from './UnifiedFindingRecommendationModal'
import CollectionSummaryModal from './CollectionSummaryModal'
import CostDriverList from './CostDriverList'

function scanStatusTone(status) {
  if (isFailedStatus(status)) return 'failed'
  if (isRunningStatus(status)) return 'running'
  if (isDoneStatus(status)) return 'done'
  return ''
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

const DOMAIN_LABELS = {
  compute: 'Compute',
  database: 'Database',
  storage: 'Storage',
  network: 'Networking',
  load_balancing: 'Load Balancing',
  security: 'Security',
  analytics: 'Analytics',
  other: 'Other',
}

const DOMAIN_ORDER = [
  'compute',
  'database',
  'storage',
  'network',
  'load_balancing',
  'security',
  'analytics',
  'other',
]

/*
 * Groups recommendations by the AWS service area (domain) the API
 * already derives from resource_catalog.yaml -- e.g. NAT Gateway /
 * Transit Gateway / VPC Endpoint all fall under "network", RDS /
 * Aurora / DynamoDB under "database". The only hardcoding here is
 * the small, fixed display-label map above; adding a new resource
 * type to an existing domain in the catalog needs no frontend change.
 */
function recommendationPriorityRank(recommendation) {
  const priority = String(
    recommendation?.priority || recommendation?.severity || 'medium',
  ).toLowerCase()

  return SEVERITY_RANK[priority] || 0
}

function groupRecommendationsByDomain(
  recommendations,
) {
  const groups = new Map()

  for (const recommendation of recommendations) {
    const key = recommendation?.domain || 'other'

    if (!groups.has(key)) groups.set(key, [])

    groups.get(key).push(recommendation)
  }

  // Most urgent item in each domain leads, matching how
  // rankedFindings already orders the findings list -- otherwise a
  // low-priority item sitting first (just because it happened to be
  // generated first) buries what actually needs attention.
  for (const items of groups.values()) {
    items.sort(
      (a, b) => recommendationPriorityRank(b) - recommendationPriorityRank(a),
    )
  }

  const ordered = DOMAIN_ORDER.filter((key) =>
    groups.has(key),
  )
    .map((key) => ({
      domain: key,
      label: DOMAIN_LABELS[key] || DOMAIN_LABELS.other,
      items: groups.get(key),
    }))
    .sort((a, b) => {
      const rankA = recommendationPriorityRank(
        a.items[0] || {},
      )
      const rankB = recommendationPriorityRank(
        b.items[0] || {},
      )
      return rankB - rankA // critical → low
    })

  for (const [key, items] of groups) {
    if (!DOMAIN_ORDER.includes(key)) {
      ordered.push({
        domain: key,
        label: DOMAIN_LABELS[key] || DOMAIN_LABELS.other,
        items,
      })
    }
  }

  return ordered
}

/*
 * Data Quality / reconciliation findings are diagnostic, not
 * actionable -- historical_unmatched alone can produce a dozen+ rows
 * (one per collection plan with no matching current resource), and
 * they mostly share the exact same title. Group by finding type with
 * a count and a real total instead of listing every raw finding.
 */
function groupFindingsByType(findings) {
  const groups = new Map()

  for (const finding of findings) {
    const key = finding?.findingType || finding?.finding_type || 'other'

    if (!groups.has(key)) {
      groups.set(key, {
        findingType: key,
        title:
          finding.fullTitle ||
          finding.title ||
          'Billing or data-quality issue',
        items: [],
        totalCost: 0,
        hasCost: false,
        services: new Set(),
      })
    }

    const group = groups.get(key)
    group.items.push(finding)

    if (finding.cost != null && Number.isFinite(Number(finding.cost))) {
      group.totalCost += Number(finding.cost)
      group.hasCost = true
    }

    // The real AWS service name for historical_unmatched /
    // billing_resource_mismatch findings lives one level down the
    // finding's own evidence, not the generic finding.service field
    // (see resolveReconciliationService) -- and a single finding
    // type can legitimately span several services (e.g. one
    // historical_unmatched group can hold both an EKS and an RDS
    // billing line), so this is a set, not a single value.
    const service = resolveReconciliationService(finding) || finding.service

    if (service) {
      group.services.add(service)
    }
  }

  return Array.from(groups.values()).map((group) => ({
    ...group,
    serviceLabel: Array.from(group.services).sort().join(', '),
  }))
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

function spendPercent(value, total) {
  const amount = Number(value)
  const denominator = Number(total)

  if (
    !Number.isFinite(amount) ||
    !Number.isFinite(denominator) ||
    amount <= 0 ||
    denominator <= 0
  ) {
    return null
  }

  return (amount / denominator) * 100
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

function FindingHeroCard({ finding, onClick, totalSpend }) {
  const spend =
    spendPercent(finding.cost, totalSpend)

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

        {spend != null && (
          <div className="fh-spend">
            {formatPct(spend)} of period spend
          </div>
        )}

        <CostScopeTag scope={finding.costScope} />

        <div className="fh-link">
          View details <span>→</span>
        </div>
      </div>
    </button>
  )
}

function FindingCard({ finding, onClick, totalSpend }) {
  const style = serviceStyle(findingService(finding))
  const spend =
    spendPercent(finding.cost, totalSpend)

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

  const style = serviceStyle(
    recommendation?.resource_service ||
      recommendation?.service ||
      'AWS service',
  )

  return (
    <button
      type="button"
      className={`recommendation-row recommendation-row-button row-pri-${String(
        priority,
      ).toLowerCase()}`}
      onClick={onClick}
    >
      <div
        className="recommendation-row-icon"
        style={{ background: style.color }}
      >
        {style.icon}
      </div>

      <div className="recommendation-main">
        <div className="recommendation-title">
          {recommendationTitle(
            recommendation,
          )}

          {resourceIdLabel && (
            <span className="recommendation-resource-id mono">
              {resourceIdLabel}
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

      <span className="row-chevron">
        →
      </span>
    </button>
  )
}


function ReconciliationRow({
  finding,
  onClick,
}) {
  const service =
    resolveReconciliationService(finding) || finding.service

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
          {service && (
            <span className="reconciliation-row-service">
              {service}
            </span>
          )}
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

  // One shared filter drives both the findings and the recommendations
  // sections below -- previously each section had its own independent
  // severity/service/region filter bar, which meant picking "High" for
  // findings said nothing about which recommendations were showing.
  const [severityFilter, setSeverityFilter] = useState('all')
  const [serviceFilter, setServiceFilter] = useState('all')
  const [regionFilter, setRegionFilter] = useState('all')

  const [dataQualityExpanded, setDataQualityExpanded] = useState(false)
  const [expandedDataQualityGroup, setExpandedDataQualityGroup] =
    useState(null)

  const [recommendationsPage, setRecommendationsPage] = useState(1)

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

  const reconciliationGroups = groupFindingsByType(reconciliationFindings)

  const reconciliationTotalCost = reconciliationGroups.reduce(
    (sum, group) => sum + group.totalCost,
    0,
  )

  // Distinct filter option lists are derived from the FULL unfiltered
  // set of both findings AND recommendations, not the currently-filtered
  // one -- otherwise picking a service would narrow the region
  // dropdown's own options too, which reads as the filter breaking
  // rather than working.
  const serviceOptions = Array.from(
    new Set([
      ...optimizationFindings.map((f) => f.service),
      ...recommendationList.map((r) => r.resource_service || r.service),
    ].filter(Boolean)),
  ).sort()

  const regionOptions = Array.from(
    new Set([
      ...optimizationFindings.map((f) => f.region),
      ...recommendationList.map((r) => r.region),
    ].filter(Boolean)),
  ).sort()

  const filtersActive =
    severityFilter !== 'all' ||
    serviceFilter !== 'all' ||
    regionFilter !== 'all'

  function clearFilters() {
    setSeverityFilter('all')
    setServiceFilter('all')
    setRegionFilter('all')
  }

  const filteredOptimizationFindings = optimizationFindings.filter(
    (finding) => {
      if (
        severityFilter !== 'all' &&
        String(finding.severity || '').toLowerCase() !== severityFilter
      ) {
        return false
      }

      if (
        serviceFilter !== 'all' &&
        finding.service !== serviceFilter
      ) {
        return false
      }

      if (
        regionFilter !== 'all' &&
        finding.region !== regionFilter
      ) {
        return false
      }

      return true
    },
  )

  // Which service is actually costing the most should surface first --
  // a finding on the #1 cost driver (e.g. a NAT Gateway billed under
  // "EC2 - Other") can otherwise sit near the bottom of the list just
  // because its own severity is Low and its cost is a shared/
  // collection-plan total (correctly null on the finding itself, per
  // the resource-cost-attribution invariant), even though the service
  // it belongs to dwarfs everything else in the account. Services not
  // present in costDrivers (e.g. only visible on a later page of the
  // Cost Drivers table) sort after every ranked one.
  const costDriverRankByService = new Map(
    costDrivers.map((driver) => [driver.service, Number(driver.rank) || 0]),
  )

  function costDriverRankFor(finding) {
    const rank = costDriverRankByService.get(finding?.service)
    return rank && rank > 0 ? rank : Number.MAX_SAFE_INTEGER
  }

  const rankedFindings =
    filteredOptimizationFindings
      .slice()
      .sort((a, b) => {
        const driverRankDiff = costDriverRankFor(a) - costDriverRankFor(b)

        if (driverRankDiff !== 0) return driverRankDiff

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

  // A recommendation only carries a numeric estimated_monthly_savings
  // when the deterministic engine could actually confirm elimination
  // of a resource-attributed cost -- most review-type recommendations
  // never populate it by design. Distinguish "nothing confirmed yet"
  // from a real, computed $0 so this doesn't read as broken.
  const confirmedSavingsCount =
    recommendationList.filter(
      (recommendation) =>
        (
          recommendation?.financial_impact
            ?.estimated_monthly_savings ??
          recommendation?.estimated_monthly_savings
        ) != null,
    ).length

  const filteredRecommendationList = recommendationList.filter(
    (recommendation) => {
      if (
        severityFilter !== 'all' &&
        String(
          recommendation.priority || recommendation.severity || 'medium',
        ).toLowerCase() !== severityFilter
      ) {
        return false
      }

      const service = recommendation.resource_service || recommendation.service

      if (serviceFilter !== 'all' && service !== serviceFilter) {
        return false
      }

      if (
        regionFilter !== 'all' &&
        recommendation.region !== regionFilter
      ) {
        return false
      }

      return true
    },
  )

  const groupedRecommendations =
    groupRecommendationsByDomain(
      filteredRecommendationList,
    )

  const RECOMMENDATIONS_PER_PAGE = 3

  // Flatten while keeping each domain group's order intact, so the
  // group headers ("Compute", "Storage", ...) still appear correctly
  // even though pagination cuts across group boundaries.
  const flatRecommendations = groupedRecommendations.flatMap(
    (group) =>
      group.items.map((recommendation) => ({
        recommendation,
        domain: group.domain,
        label: group.label,
      })),
  )

  const recommendationsTotalPages = Math.max(
    1,
    Math.ceil(
      flatRecommendations.length / RECOMMENDATIONS_PER_PAGE,
    ),
  )

  const safeRecommendationsPage = Math.min(
    recommendationsPage,
    recommendationsTotalPages,
  )

  const pagedRecommendationEntries = flatRecommendations.slice(
    (safeRecommendationsPage - 1) * RECOMMENDATIONS_PER_PAGE,
    safeRecommendationsPage * RECOMMENDATIONS_PER_PAGE,
  )

  // Consecutive same-domain entries on this page share one
  // .recommendation-group wrapper (tight spacing within a domain, wider
  // spacing between domains) -- pagination can start/end mid-group, so
  // this is recomputed per page rather than reusing groupedRecommendations
  // directly.
  const pageRecommendationChunks = []

  for (const entry of pagedRecommendationEntries) {

    const item = {
      recommendation: entry.recommendation,
      key:
        recommendationId(entry.recommendation) ||
        `${entry.domain}-${pageRecommendationChunks.length}`,
    }

    const lastChunk =
      pageRecommendationChunks[
        pageRecommendationChunks.length - 1
      ]

    if (lastChunk && lastChunk.domain === entry.domain) {
      lastChunk.items.push(item)
    } else {
      pageRecommendationChunks.push({
        domain: entry.domain,
        label: entry.label,
        items: [item],
      })
    }
  }

  useEffect(() => {
    setRecommendationsPage(1)
  }, [severityFilter, serviceFilter, regionFilter])

  return (
    <div className="results-page">

      <div className="header-row">
        <div className="headline">

          <h1>
            Optimization Results
          </h1>

          <div className="sub">
            {formatDate(resultsScan?.start_date)}
            {' → '}
            {formatDate(resultsScan?.end_date)}
            {' · '}
            {resultsScan?.region || 'All regions'}
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
              Collection Summary
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
              No analysis results
            </h3>

            <p>
              Run an analysis to identify
              AWS cost optimization
              opportunities.
            </p>

            <button
              type="button"
              className="small-btn primary-btn"
              onClick={onRunAnalysis}
            >
              Run Analysis
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

                  <div className="results-summary-period">
                    {formatDate(resultsScan.start_date)}
                    <span className="results-summary-period-arrow">
                      →
                    </span>
                    {formatDate(resultsScan.end_date)}
                  </div>

                  <div className="results-summary-meta">
                    <span className="results-summary-badge">
                      {resultsScan.region ||
                        'All regions'}
                    </span>

                    <span className="results-summary-badge mono">
                      Scan #{scanNumber}
                    </span>
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

                  <span
                    className={`stat-v stat-v-status ${scanStatusTone(
                      resultsScan.status,
                    )}`}
                  >
                    <span className="stat-status-dot" />
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

            {(optimizationFindings.length > 0 ||
              recommendationList.length > 0) && (
              <section className="panel section-gap results-filter-panel">

                <div className="panel-head">
                </div>

                <div className="results-filter-bar">

                  <div className="cost-explorer-segmented results-filter-segmented">
                    {['all', 'critical', 'high', 'medium', 'low'].map(
                      (option) => (
                        <button
                          type="button"
                          key={option}
                          className={
                            severityFilter === option ? 'active' : ''
                          }
                          onClick={() => setSeverityFilter(option)}
                        >
                          {option === 'all' ? 'All' : sevLabel(option)}
                        </button>
                      ),
                    )}
                  </div>

                  <div className="cost-explorer-control">
                    <span>Service</span>
                    <select
                      value={serviceFilter}
                      onChange={(event) =>
                        setServiceFilter(event.target.value)
                      }
                    >
                      <option value="all">All services</option>
                      {serviceOptions.map((service) => (
                        <option key={service} value={service}>
                          {service}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="cost-explorer-control">
                    <span>Region</span>
                    <select
                      value={regionFilter}
                      onChange={(event) =>
                        setRegionFilter(event.target.value)
                      }
                    >
                      <option value="all">All regions</option>
                      {regionOptions.map((region) => (
                        <option key={region} value={region}>
                          {region}
                        </option>
                      ))}
                    </select>
                  </div>

                  {filtersActive && (
                    <button
                      type="button"
                      className="small-btn results-filter-clear"
                      onClick={clearFilters}
                    >
                      Clear filters
                    </button>
                  )}

                </div>

              </section>
            )}

            <section className="panel section-gap">

              <div className="panel-head">

                <div>

                  <div className="eyebrow">
                    / Findings
                  </div>

                  <div className="panel-title">
                    What needs attention
                  </div>

                </div>

                <span className="snapshot-count">
                  {rankedFindings.length}{' '}
                  {rankedFindings.length === 1 ? 'finding' : 'findings'}
                  {filtersActive &&
                    rankedFindings.length !== optimizationFindings.length && (
                      <span className="snapshot-count-of">
                        {' '}
                        of {optimizationFindings.length}
                      </span>
                    )}
                </span>

              </div>

              {!optimizationFindings.length ? (
                <div className="chart-empty">
                  No optimization issues were
                  identified in this analysis.
                </div>
              ) : !rankedFindings.length ? (
                <div className="chart-empty">
                  No findings match the current filters.
                </div>
              ) : (
                <div className="findings-card-grid">

                  <FindingHeroCard
                    finding={rankedFindings[0]}
                    onClick={() =>
                      openFinding(rankedFindings[0])
                    }
                  />

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

            </section>

            <section className="panel section-gap recommendations-results-panel">

              <div className="panel-head">

                <div>

                  <div className="eyebrow">
                    / Recommendations
                  </div>

                  <div className="panel-title">
                    What to do next
                  </div>

                </div>

                <span className="snapshot-count">
                  {filteredRecommendationList.length}{' '}
                  {filteredRecommendationList.length === 1
                    ? 'action'
                    : 'actions'}
                  {filtersActive &&
                    filteredRecommendationList.length !==
                      recommendationList.length && (
                      <span className="snapshot-count-of">
                        {' '}
                        of {recommendationList.length}
                      </span>
                    )}
                </span>

              </div>

              {!recommendationList.length ? (
                <div className="chart-empty">
                  No optimization actions were
                  generated for this scan.
                </div>
              ) : !filteredRecommendationList.length ? (
                <div className="chart-empty">
                  No recommendations match the current filters.
                </div>
              ) : (
                <>
                  <div className="recommendations-list">

                    {pageRecommendationChunks.map(
                      (chunk) => (
                        <div
                          className="recommendation-group"
                          key={`${chunk.domain}-${chunk.items[0].key}`}
                        >

                          <div className="recommendation-group-head">
                            {chunk.label}
                          </div>

                          {chunk.items.map(
                            (item) => (
                              <RecommendationRow
                                key={item.key}
                                recommendation={
                                  item.recommendation
                                }
                                relatedFinding={
                                  findRelatedFinding(
                                    item.recommendation,
                                    findingList,
                                  )
                                }
                                onClick={() =>
                                  openRecommendation(
                                    item.recommendation,
                                  )
                                }
                              />
                            ),
                          )}

                        </div>
                      ),
                    )}

                  </div>

                  {recommendationsTotalPages > 1 && (
                    <div className="cost-explorer-pager recommendations-pager">
                      <button
                        type="button"
                        className="small-btn"
                        onClick={() =>
                          setRecommendationsPage((page) =>
                            Math.max(1, page - 1),
                          )
                        }
                        disabled={
                          safeRecommendationsPage <= 1
                        }
                      >
                        ← 
                      </button>

                      <span className="cost-explorer-pager-info mono">
                        Page {safeRecommendationsPage} of{' '}
                        {recommendationsTotalPages} ·{' '}
                        {pluralize(
                          flatRecommendations.length,
                          'action',
                        )}
                      </span>

                      <button
                        type="button"
                        className="small-btn"
                        onClick={() =>
                          setRecommendationsPage((page) =>
                            Math.min(
                              recommendationsTotalPages,
                              page + 1,
                            ),
                          )
                        }
                        disabled={
                          safeRecommendationsPage >=
                          recommendationsTotalPages
                        }
                      >
                         →
                      </button>
                    </div>
                  )}
                </>
              )}

            </section>

            <section
              className={`panel section-gap data-quality-panel ${
                dataQualityExpanded ? 'expanded' : ''
              }`}
            >

              <button
                type="button"
                className="data-quality-toggle"
                onClick={() =>
                  setDataQualityExpanded((value) => !value)
                }
                aria-expanded={dataQualityExpanded}
              >

                <div className="panel-head">

                  <div>

                    <div className="eyebrow">
                      / Data Quality
                    </div>

                    <div className="panel-title">
                      Billing & resource checks
                    </div>

                  </div>

                  <div className="data-quality-head-right">

                    <span className="snapshot-count">
                      {reconciliationFindings.length}{' '}
                      {reconciliationFindings.length === 1
                        ? 'check'
                        : 'checks'}
                    </span>

                    <span className="row-chevron">
                      {dataQualityExpanded ? '⌃' : '⌄'}
                    </span>

                  </div>

                </div>

                {!dataQualityExpanded &&
                  reconciliationFindings.length > 0 && (
                    <p className="data-quality-summary-line">
                      {reconciliationGroups.length}{' '}
                      notice{' '}
                      {reconciliationGroups.length === 1
                        ? 'type'
                        : 'types'}
                      {reconciliationTotalCost > 0 && (
                        <>
                          {' '}
                          · {formatMoneyOrDash(reconciliationTotalCost)}{' '}
                          historical cost without a current resource
                        </>
                      )}
                      {' '}
                      · Informational
                    </p>
                  )}

              </button>

              {dataQualityExpanded &&
                (!reconciliationFindings.length ? (
                  <div className="chart-empty">
                    No billing or resource
                    reconciliation issues were
                    detected.
                  </div>
                ) : (
                  <div className="reconciliation-groups">

                    {reconciliationGroups.map((group) => {
                      const isOpen =
                        expandedDataQualityGroup === group.findingType

                      return (
                        <div
                          className="reconciliation-group"
                          key={group.findingType}
                        >

                          <button
                            type="button"
                            className="reconciliation-group-head"
                            onClick={() =>
                              setExpandedDataQualityGroup(
                                isOpen ? null : group.findingType,
                              )
                            }
                            aria-expanded={isOpen}
                          >
                            <span className="reconciliation-group-title-wrap">
                              <span className="reconciliation-group-title">
                                {group.title}
                              </span>

                              {group.serviceLabel && (
                                <span className="reconciliation-group-service">
                                  {group.serviceLabel}
                                </span>
                              )}
                            </span>

                            <span className="reconciliation-group-count">
                              {group.items.length}
                            </span>

                            <span className="reconciliation-group-cost mono">
                              {group.hasCost
                                ? formatMoneyOrDash(group.totalCost)
                                : '—'}
                            </span>

                            <span className="row-chevron">
                              {isOpen ? '⌃' : '⌄'}
                            </span>
                          </button>

                          {isOpen && (
                            <div className="reconciliation-list">
                              {group.items.map((finding) => (
                                <ReconciliationRow
                                  key={normalizeFindingKey(finding)}
                                  finding={finding}
                                  onClick={() => openFinding(finding)}
                                />
                              ))}
                            </div>
                          )}

                        </div>
                      )
                    })}

                  </div>
                ))}

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