import { sevLabel, truncateId } from '../utils/format'
import { serviceStyle } from '../utils/serviceStyle'

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

  if (
    Array.isArray(finding?.condition_groups) &&
    finding.condition_groups.length
  ) {
    const ids = finding.condition_groups
      .map((group) => group?.resource_id)
      .filter(Boolean)

    if (ids.length) {
      return new Set(ids).size
    }
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

  for (const group of finding?.condition_groups || []) {
    if (group?.resource_id && !ids.includes(group.resource_id)) {
      ids.push(group.resource_id)
    }
  }

  if (Array.isArray(finding?.conditions)) {
    for (const condition of finding.conditions) {
      if (
        condition?.resource_id &&
        !ids.includes(condition.resource_id)
      ) {
        ids.push(condition.resource_id)
      }
    }
  }

  return ids
}

function formatConditionValue(value) {
  if (value == null) return 'N/A'

  if (typeof value === 'object') {
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  }

  return String(value)
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

function isHistoricalFinding(finding) {
  const historicalTypes = new Set([
    'historical_unmatched',
    'historical_spend_no_current_resource',
    'historical_resource_not_found',
    'collection_no_matching_resources',
    'billing_resource_mismatch',
    'billing_no_cost',
    'billing_reconciliation_unknown',
  ])

  return historicalTypes.has(finding?.finding_type)
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

function buildConditionGroups(finding) {
  if (!Array.isArray(finding?.condition_groups)) {
    return []
  }

  return finding.condition_groups.map((group) => ({
    resourceId: group?.resource_id || null,

    statements: Array.isArray(group?.statements)
      ? group.statements.map((statement) => ({
          name: statement?.name || '',
          label: statement?.label || statement?.name || '',
          expected: formatConditionValue(statement?.expected),
          actual: formatConditionValue(statement?.actual),
          status: statement?.status || null,
          statusClass: statusClass(statement?.status),
          description: statement?.description || '',
          source: Array.isArray(statement?.source)
            ? statement.source
            : [],
          supportsFinding:
            statement?.supports_finding !== false,
        }))
      : [],
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
    v: cost != null ? `$${cost.toFixed(2)}` : 'Not available',
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
    finding?.metadata?.region

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

  return {
    id: String(finding?.id ?? ''),
    findingType: finding?.finding_type || null,

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

    cost:
      finding?.cost != null
        ? Number(finding.cost)
        : null,

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

    observationPeriod:
      finding?.observation_period || null,

    metadata:
      finding?.metadata || {},

    conditionGroups:
      buildConditionGroups(finding),

    evidenceItems:
      Array.isArray(finding?.evidence_items)
        ? finding.evidence_items
        : [],

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

    costLabel:
      finding?.cost != null
        ? `$${Number(finding.cost).toFixed(2)}`
        : null,
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

export function countBySeverity(findings) {
  const counts = {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }

  const values =
    findings && !Array.isArray(findings)
      ? Object.values(findings)
      : Array.isArray(findings)
        ? findings
        : []

  for (const finding of values) {
    const severity = String(
      finding?.severity || 'low',
    ).toLowerCase()

    if (
      Object.prototype.hasOwnProperty.call(
        counts,
        severity,
      )
    ) {
      counts[severity] += 1
    } else {
      counts.low += 1
    }
  }

  return counts
}