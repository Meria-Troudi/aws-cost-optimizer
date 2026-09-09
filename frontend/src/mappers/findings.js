import { formatMoneyOrDash, sevLabel, truncateId } from '../utils/format'
import { serviceStyle } from '../utils/serviceStyle'

// Finding types the backend actually emits for billing/resource
// reconciliation mismatches (see aws_cost_optimizer/analysis/
// reconciliation.py) -- kept in sync with the real finding_type
// strings, not a superset of hypothetical ones.
export const RECONCILIATION_TYPES = [
  'historical_unmatched',
  'billing_resource_mismatch',
]

function resolveTitle(finding) {
  if (finding?.title && !finding.title.includes('_')) {
    return finding.title
  }

  if (finding?.summary && !finding.summary.includes('_')) {
    return finding.summary
  }

  return (finding?.finding_type || 'Finding')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function countResources(finding) {
  if (
    finding?.resource_count != null &&
    Number(finding.resource_count) >= 0
  ) {
    return Number(finding.resource_count)
  }

  if (Array.isArray(finding?.resource_ids) && finding.resource_ids.length) {
    return finding.resource_ids.length
  }

  const match = String(finding?.reason || '').match(
    /(\d+)\s+resources?\s+satisfy/i,
  )

  if (match) {
    return Number(match[1])
  }

  if (finding?.resource_id) {
    return 1
  }

  return 0
}

function collectResourceIds(finding) {
  const ids = []

  if (Array.isArray(finding?.resource_ids)) {
    for (const id of finding.resource_ids) {
      if (id && !ids.includes(id)) {
        ids.push(id)
      }
    }
  }

  if (finding?.resource_id && !ids.includes(finding.resource_id)) {
    ids.push(finding.resource_id)
  }

  return ids
}

// historical_unmatched / billing_resource_mismatch findings never set a
// top-level finding.cost, and their "metadata" field is consistently
// null in practice -- confirmed against live scan output, the real
// amount lives under the first condition's value.cost instead (see
// aws_cost_optimizer/collection/validation.py). Without this fallback
// these findings always show "-" for cost, even though a real number
// exists one level down.
function resolveReconciliationCost(finding) {
  if (!RECONCILIATION_TYPES.includes(finding?.finding_type)) {
    return null
  }

  const metadataCost = finding?.metadata?.cost

  if (metadataCost != null && Number.isFinite(Number(metadataCost))) {
    return Number(metadataCost)
  }

  const conditionCost = finding?.conditions?.[0]?.value?.cost

  if (conditionCost != null && Number.isFinite(Number(conditionCost))) {
    return Number(conditionCost)
  }

  return null
}

// Same shape as resolveReconciliationCost above -- the billing line's
// own region lives under conditions[0].value.region, not metadata,
// which matters for an all-regions scan where the scan-level region
// argument is null and there is nothing else to fall back to.
function resolveReconciliationRegion(finding) {
  if (!RECONCILIATION_TYPES.includes(finding?.finding_type)) {
    return null
  }

  return (
    finding?.metadata?.region ||
    finding?.conditions?.[0]?.value?.region ||
    null
  )
}

// Same shape again: backend/api/presenters/finding_presenter.py's
// _extract_service() only checks evidence.service / evidence.billing.service,
// neither of which these two finding types populate, so it falls back to
// a generic resource_type alias (e.g. "RDS", or an untranslated "Eks
// Cluster" for types with no alias entry) instead of the real AWS
// service name that's sitting right there in conditions[0].value.service.
export function resolveReconciliationService(finding) {
  if (!RECONCILIATION_TYPES.includes(finding?.finding_type)) {
    return null
  }

  return finding?.conditions?.[0]?.value?.service || null
}

function formatConditionValue(value, unit = null) {
  if (value == null) return 'N/A'

  if (Array.isArray(value)) {
    return value.length
      ? value.map((item) => formatConditionValue(item)).join(', ')
      : 'None'
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value)

    if (!entries.length) {
      return 'N/A'
    }

    // Summarize rather than expand a nested array/object -- some
    // analyzers deliberately attach a full diagnostic dict as a
    // condition's value (e.g. Transit Gateway's telemetry
    // diagnostics), which used to fall through to a raw
    // JSON.stringify of the whole structure here. A table cell isn't
    // the place to inspect that field-by-field; one level of
    // key: value pairs, with nested structures reduced to a size
    // hint, is enough supporting evidence.
    return entries
      .map(([k, v]) => {
        const label = k.replace(/_/g, ' ')

        if (v == null) {
          return `${label}: —`
        }

        if (Array.isArray(v)) {
          return `${label}: ${v.length} item${v.length === 1 ? '' : 's'}`
        }

        if (typeof v === 'object') {
          const nestedCount = Object.keys(v).length
          return `${label}: {${nestedCount} field${
            nestedCount === 1 ? '' : 's'
          }}`
        }

        return `${label}: ${String(v)}`
      })
      .join(', ')
  }

  if (typeof value === 'boolean') {
    return value ? 'Yes' : 'No'
  }

  return unit ? `${value} ${unit}` : String(value)
}

function statusClass(status) {
  if (!status) return ''

  const normalized = String(status).toLowerCase()

  if (
    normalized === 'fail' ||
    normalized === 'failed' ||
    normalized === 'zero'
  ) {
    return 'cond-fail'
  }

  if (normalized === 'info') {
    return 'cond-info'
  }

  if (
    normalized === 'pass' ||
    normalized === 'passed' ||
    normalized === 'detected'
  ) {
    return 'cond-pass'
  }

  return ''
}

// Mirrors aws_cost_optimizer/analysis/billing.py's ATTRIBUTION_SCOPES.
// "resource" is the only scope where a cost figure is this specific
// resource's own confirmed cost -- everything else is shared/indirect
// evidence and must not be presented as if it were this resource's cost.
const ATTRIBUTION_INFO = {
  resource: {
    label: 'Resource cost',
    tone: 'good',
    tooltip:
      'Confirmed as this resource’s own cost.',
  },
  collection_plan: {
    label: 'Shared cost',
    tone: 'neutral',
    tooltip:
      'Shared across multiple resources on this billing line; not confirmed as this one’s exact share.',
  },
  service: {
    label: 'Service-level',
    tone: 'neutral',
    tooltip:
      'Attributed at the service level, not confirmed for this specific resource.',
  },
  historical: {
    label: 'Historical',
    tone: 'neutral',
    tooltip:
      'Historical billing evidence with no matching current resource.',
  },
  unknown: {
    label: 'Unattributed',
    tone: 'neutral',
    tooltip:
      'Cost attribution could not be confirmed for this resource.',
  },
}

export function attributionInfo(scope) {
  const key = String(scope || '')
    .trim()
    .toLowerCase()

  return (
    ATTRIBUTION_INFO[key] ||
    ATTRIBUTION_INFO.unknown
  )
}

const RECONCILIATION_TYPE_SET = new Set(
  RECONCILIATION_TYPES,
)

function isHistoricalFinding(finding) {
  return RECONCILIATION_TYPE_SET.has(
    finding?.finding_type,
  )
}

function getHistoricalRegion(finding) {
  return (
    finding?.metadata?.region ||
    finding?.region ||
    String(finding?.resource_id || '')
      .match(/^historical-unmatched:([^:]+):/)?.[1] ||
    String(finding?.resource_id || '')
      .match(/^not-found:([^:]+):/)?.[1]
  )
}

function resourceLabel(finding, resourceIds, resourceCount) {
  if (isHistoricalFinding(finding)) {
    const region = getHistoricalRegion(finding)

    if (region && region !== 'All regions') {
      return region
    }

    return 'No current match'
  }

  if (resourceCount > 1) {
    return `${resourceCount} resources`
  }

  const id =
    resourceIds[0] ||
    finding?.resource_id ||
    finding?.primary_resource_id

  return id ? truncateId(String(id), 16) : '—'
}

function conditionStatus(statement) {
  if (statement?.observed === true) return 'detected'
  if (statement?.observed === false) return 'zero'
  return 'info'
}

function conditionLabel(statement) {
  if (statement?.name) {
    return String(statement.name)
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase())
  }

  return statement?.description || 'Condition'
}

// Backend sends a flat list of EvidenceStatement dicts
// ({name, value, description, source, evidence_keys, unit,
// observed}) per finding — there is no per-resource grouping and no
// expected/actual distinction, unlike the older condition_groups
// shape this used to expect.
function buildEvidenceItems(finding) {
  const conditions = Array.isArray(finding?.conditions)
    ? finding.conditions
    : []

  return conditions.map((statement) => ({
    resourceId: finding?.resource_id || '',

    label: conditionLabel(statement),

    expected: '—',

    actual: formatConditionValue(
      statement?.value,
      statement?.unit,
    ),

    status: conditionStatus(statement),
    statusClass: statusClass(conditionStatus(statement)),

    description: statement?.description || '',

    source: Array.isArray(statement?.source)
      ? statement.source
      : [],

    supports_finding: statement?.observed !== false,
  }))
}

function buildDependencies(
  finding,
  resourceCount,
  region,
) {
  const rows = [
    {
      k: 'Service',
      v: finding?.service || finding?.resource_type || 'Unknown',
    },
    {
      k: 'Region',
      v: region || 'All regions',
    },
    {
      k: 'Affected resources',
      v: String(resourceCount),
    },
  ]

  if (finding?.category) {
    rows.push({
      k: 'Category',
      v: finding.category,
    })
  }

  if (finding?.billing_details) {
    const billing = finding.billing_details

    if (billing.billing_class) {
      rows.push({
        k: 'Billing class',
        v: billing.billing_class,
      })
    }

    if (billing.resource_class) {
      rows.push({
        k: 'Discovered class',
        v: billing.resource_class,
      })
    }
  }

  return rows
}

function buildCostCards(finding) {
  const cards = []

  const cost =
    finding?.cost != null
      ? Number(finding.cost)
      : null

  cards.push({
    k: 'Analysis-period cost',
    v: cost != null ? formatMoneyOrDash(cost) : 'Not available',
  })

  if (finding?.billing_details) {
    const billing = finding.billing_details

    const usageType = billing.usage_type
    if (usageType) {
      cards.push({
        k: 'Usage type',
        v: String(usageType),
      })
    }

    const attribution = billing.attribution_scope
    if (attribution) {
      cards.push({
        k: 'Cost attribution',
        v: String(attribution).replace(/_/g, ' '),
      })
    }
  } else {
    cards.push({
      k: 'Cost source',
      v: 'AWS Cost Explorer',
    })
  }

  return cards
}

export function mapApiFinding(finding, region = null) {
  const service =
    finding?.service ||
    String(finding?.resource_type || 'Unknown')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase())
      .replace(/^Nat Gateway$/i, 'NAT Gateway')

  const style = serviceStyle(service)

  const severity = String(
    finding?.severity || 'low',
  ).toLowerCase()

  const resourceIds = collectResourceIds(finding)

  const resourceCount =
    countResources(finding) ||
    (resourceIds.length ? resourceIds.length : 1)

  const title =
    finding?.title ||
    finding?.summary ||
    resolveTitle(finding)

  const scanRegion =
    region ||
    finding?.region ||
    finding?.metadata?.region ||
    resolveReconciliationRegion(finding)

  const displayRegion =
    scanRegion &&
    scanRegion !== '—' &&
    scanRegion !== 'account'
      ? scanRegion
      : 'All regions'

  const recommendationEligible =
    finding?.recommendation_eligible !== false

  const blocksOptimization =
    Boolean(finding?.blocks_optimization)

  const resourceTypeLabel = finding?.resource_type
    ? String(finding.resource_type)
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase())
    : null

  const resolvedCost =
    finding?.cost != null
      ? Number(finding.cost)
      : resolveReconciliationCost(finding)

  // finding.cost is only ever non-null when reconciliation confirmed it
  // as THIS resource's own cost -- everything else (collection_plan/
  // service/historical attribution) leaves it null on purpose, per
  // aws_cost_optimizer/analysis/financial.py. That's correct, but it
  // also means every shared-cost finding rendered as a blank dash with
  // nothing to look at. billing_details.amount still carries the real
  // billing-line total in that case; show it, clearly marked as shared
  // (never as this resource's own figure) rather than showing nothing.
  const sharedCostAmount =
    resolvedCost == null && finding?.billing_details?.amount != null
      ? Number(finding.billing_details.amount)
      : null

  const costLabel =
    resolvedCost != null
      ? formatMoneyOrDash(resolvedCost)
      : sharedCostAmount != null && Number.isFinite(sharedCostAmount)
        ? `${formatMoneyOrDash(sharedCostAmount)} `
        : null

  return {
    id: String(finding?.id ?? ''),
    findingType: finding?.finding_type || null,

    // Kept as the raw machine key (e.g. "aurora_cluster") for any
    // code that needs to match/compare it, alongside the humanized
    // label below for direct display.
    resource_type: finding?.resource_type || null,
    resourceTypeLabel,

    severity,
    sevLabel: sevLabel(severity),

    icon: style.icon,
    iconBg: style.color,

    service,

    serviceFilter:
      service === 'NAT Gateway'
        ? 'NAT'
        : service.split(' ')[0]?.toUpperCase() || 'OTHER',

    resource:
      resourceIds[0] ||
      finding?.resource_id ||
      null,

    resourceLabel: resourceLabel(
      finding,
      resourceIds,
      resourceCount,
    ),

    resourceIds,
    resourceCount,

    title,
    fullTitle: title,

    region:
      finding?.region &&
      finding.region !== '—'
        ? finding.region
        : displayRegion,

    cost: resolvedCost,

    reason:
      finding?.reason ||
      title,

    confidence:
      finding?.confidence ?? null,

    category:
      finding?.category || null,

    recommendationEligible,

    blocksOptimization,

    billingDetails:
      finding?.billing_details || null,

    costScope:
      finding?.cost_scope ||
      finding?.billing_details
        ?.attribution_scope ||
      null,

    observationPeriod:
      finding?.observation_period || null,

    metadata:
      finding?.metadata || {},

    evidenceItems:
      buildEvidenceItems(finding),

    metrics:
      Array.isArray(finding?.metrics)
        ? finding.metrics
        : [],

    limitations:
      Array.isArray(finding?.limitations)
        ? finding.limitations
        : [],

    topo: buildDependencies(
      finding,
      resourceCount,
      displayRegion,
    ),

    topoWarn:
      Array.isArray(finding?.limitations) &&
      finding.limitations.length
        ? finding.limitations.join(' ')
        : 'Review dependencies before acting.',

    costCards:
      buildCostCards(finding),

    evidenceSummary:
      Array.isArray(finding?.evidence_summary)
        ? finding.evidence_summary
        : [],

    impact:
      finding?.impact || {},

    costLabel,
  }
}

export function mapApiFindings(
  apiFindings,
  region = null,
) {
  const mapped = {}

  if (!Array.isArray(apiFindings)) {
    return mapped
  }

  for (const finding of apiFindings) {
    const mappedFinding = mapApiFinding(
      finding,
      region,
    )

    if (mappedFinding.id) {
      mapped[mappedFinding.id] = mappedFinding
    }
  }

  return mapped
}

export function mapApiRecommendations(
  recommendations,
  findings = {},
) {
  if (!Array.isArray(recommendations)) {
    return []
  }

  return recommendations.map((recommendation, index) => {
    const linkedFindingId =
      recommendation?.finding_id != null
        ? String(recommendation.finding_id)
        : null

    const matched =
      linkedFindingId
        ? findings[linkedFindingId]
        : null

    const affectedResources =
      Array.isArray(
        recommendation?.affected_resources,
      ) && recommendation.affected_resources.length
        ? recommendation.affected_resources
        : matched?.resourceIds || []

    const resourceCount =
      recommendation?.affected_resource_count != null
        ? Number(
            recommendation.affected_resource_count,
          )
        : affectedResources.length ||
          matched?.resourceCount ||
          1

    const reason =
      recommendation?.reason ||
      recommendation?.rationale ||
      recommendation?.explanation ||
      matched?.reason ||
      ''

    return {
      ...recommendation,

      id: String(
        recommendation?.id ??
          `recommendation-${index}`,
      ),

      meta:
        recommendation?.meta ||
        (
          resourceCount > 1
            ? `${resourceCount} resources affected`
            : matched?.resourceLabel ||
              'Review required'
        ),

      priorityLabel: sevLabel(
        recommendation?.priority ||
          'medium',
      ),

      linkedFindingId:
        matched
          ? linkedFindingId
          : null,

      rationale: reason,
      reason,

      showExplanation:
        Boolean(reason),

      affectedResources,

      affectedResourceCount:
        resourceCount,

      status:
        recommendation?.status ||
        'pending_review',
    }
  })
}