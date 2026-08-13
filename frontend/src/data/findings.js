import { sevLabel, truncateId } from '../utils/format'
import { serviceStyle } from '../utils/serviceStyle'

const FINDING_TITLES = {
  nat_gateway_no_observed_activity: 'NAT Gateway with no observed activity',
  nat_gateway_no_activity: 'NAT Gateway with no observed activity',
  nat_gateway_low_utilization: 'NAT Gateway with low utilization',
  nat_gateway_aws_service_traffic: 'NAT Gateway routing AWS service traffic',
  nat_gateway_cross_az: 'NAT Gateway with cross-AZ traffic',
  rds_billing_resource_mismatch: 'RDS billing/resource mismatch',
  rds_unmatched_billing_usage: 'Unmatched RDS billing usage',
  collection_no_matching_resources: 'No matching resources found during collection',
}

function resolveTitle(finding) {
  if (finding.title && !finding.title.includes('_')) return finding.title
  if (finding.summary && !finding.summary.includes('_')) return finding.summary
  return (
    FINDING_TITLES[finding.finding_type] ||
    (finding.finding_type || 'Finding').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
  )
}

function countResources(finding) {
  if (finding.resource_count > 0) return finding.resource_count

  if (finding.condition_groups?.length) return finding.condition_groups.length

  const match = (finding.reason || '').match(/(\d+)\s+resources\s+satisfy/i)
  if (match) return Number(match[1])

  if (finding.resource_ids?.length) return finding.resource_ids.length

  const conditions = finding.conditions
  if (Array.isArray(conditions)) {
    const blockIds = conditions
      .filter((c) => c && typeof c === 'object' && c.resource_id)
      .map((c) => c.resource_id)
    if (blockIds.length) return blockIds.length
  }

  return finding.resource_id ? 1 : 0
}

function collectResourceIds(finding) {
  if (finding.resource_ids?.length) return finding.resource_ids

  const ids = []
  if (finding.resource_id) ids.push(finding.resource_id)

  for (const group of finding.condition_groups || []) {
    if (group?.resource_id && !ids.includes(group.resource_id)) {
      ids.push(group.resource_id)
    }
  }

  const conditions = finding.conditions
  if (Array.isArray(conditions)) {
    for (const block of conditions) {
      if (block?.resource_id && !ids.includes(block.resource_id)) {
        ids.push(block.resource_id)
      }
    }
  }

  return ids
}

function resourceLabel(finding, resourceIds, resourceCount) {
  if (resourceCount > 1) return `${resourceCount} resources`
  const id = resourceIds[0] || finding.resource_id
  return id ? truncateId(id, 16) : '—'
}

function formatConditionValue(value) {
  if (value == null) return 'N/A'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function statusClass(status) {
  if (!status) return ''
  const s = String(status).toLowerCase()
  if (s === 'fail' || s === 'zero') return 'cond-fail'
  if (s === 'info') return 'cond-info'
  if (s === 'pass' || s === 'detected') return 'cond-pass'
  return ''
}

export function mapApiFinding(finding, region = null) {
  const service =
    finding.service ||
    (finding.resource_type || 'unknown')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase())
      .replace(/^Nat Gateway$/i, 'NAT Gateway')

  const icons = serviceStyle(service)
  const severity = (finding.severity || 'low').toLowerCase()
  const resourceIds = collectResourceIds(finding)
  const resourceCount = countResources(finding) || resourceIds.length || 1
  const title = resolveTitle(finding)
  const scanRegion = region || finding.region
  const displayRegion =
    scanRegion && scanRegion !== '—' && scanRegion !== 'account'
      ? scanRegion
      : 'All regions'

  const conditionGroups = (finding.condition_groups || []).map((group) => ({
    resourceId: group.resource_id,
    statements: (group.statements || []).map((stmt) => ({
      name: stmt.name,
      label: stmt.label || stmt.name,
      expected: formatConditionValue(stmt.expected),
      actual: formatConditionValue(stmt.actual),
      status: stmt.status,
      statusClass: statusClass(stmt.status),
      description: stmt.description || '',
      source: Array.isArray(stmt.source) ? stmt.source : [],
      supportsFinding: stmt.supports_finding !== false,
    })),
  }))

  return {
    id: String(finding.id),
    findingType: finding.finding_type,
    severity,
    sevLabel: sevLabel(severity),
    icon: icons.icon,
    iconBg: icons.color,
    service,
    serviceFilter: service === 'NAT Gateway' ? 'NAT' : service.split(' ')[0].toUpperCase(),
    resource: resourceIds[0] || finding.resource_id,
    resourceLabel: resourceLabel(finding, resourceIds, resourceCount),
    resourceIds,
    resourceCount,
    title,
    fullTitle: title,
    region: finding.region && finding.region !== '—' ? finding.region : displayRegion,
    cost: finding.cost,
    costLabel: finding.cost_label || 'Not estimated',
    reason: finding.reason || title,
    confidence: finding.confidence,
    category: finding.category,
    blocksOptimization: finding.blocks_optimization,
    billingDetails: finding.billing_details,
    observationPeriod: finding.observation_period,
    metadata: finding.metadata || {},
    conditionGroups,
    evidenceItems: finding.evidence_items || [],
    metrics: finding.metrics || [],
    limitations: finding.limitations || [],
    topo: buildDependencies(finding, resourceIds, resourceCount, displayRegion),
    topoWarn:
      (Array.isArray(finding.limitations) ? finding.limitations.join(' ') : '') ||
      'Review dependencies before acting.',
    costCards: buildCostCards(finding),
    costStatus: finding.recommendation_eligible
      ? 'Recommendation eligible'
      : finding.blocks_optimization
        ? 'Blocks optimization until resolved'
        : 'Cost not estimated',
  }
}

function buildDependencies(finding, resourceIds, resourceCount, region) {
  const rows = [
    { k: 'Service', v: finding.service || finding.resource_type },
    { k: 'Region', v: region },
    { k: 'Affected resources', v: String(resourceCount) },
  ]

  if (finding.category) {
    rows.push({ k: 'Category', v: finding.category })
  }

  if (finding.billing_details) {
    const bd = finding.billing_details
    if (bd.billing_class) rows.push({ k: 'Billing class', v: bd.billing_class })
    if (bd.resource_class) rows.push({ k: 'Discovered class', v: bd.resource_class })
  }

  return rows
}

function buildCostCards(finding) {
  return [
    { k: 'Analysis-period cost', v: finding.cost != null ? `$${finding.cost}` : 'Not available' },
    { k: 'Cost source', v: 'AWS Cost Explorer' },
  ]
}

export function mapApiFindings(apiFindings, region) {
  const mapped = {}
  for (const f of apiFindings) {
    mapped[String(f.id)] = mapApiFinding(f, region)
  }
  return mapped
}

export function mapApiRecommendations(recommendations, findings) {
  return recommendations.map((rec) => {
    const linkedFindingId =
      rec.finding_id != null ? String(rec.finding_id) : null
    const matched = linkedFindingId ? findings[linkedFindingId] : null

    const resourceCount =
      rec.affected_resource_count ||
      rec.affected_resources?.length ||
      matched?.resourceCount ||
      1

    const affectedResources =
      rec.affected_resources?.length
        ? rec.affected_resources
        : matched?.resourceIds || []

    const meta =
      rec.meta ||
      (resourceCount > 1
        ? `${resourceCount} resources affected`
        : matched?.resourceLabel || 'Review required')

    const reason = rec.reason || rec.rationale || rec.explanation || matched?.reason || ''

    return {
      ...rec,
      meta,
      priorityLabel: sevLabel(rec.priority || 'medium'),
      linkedFindingId: matched ? linkedFindingId : null,
      rationale: reason,
      reason,
      showExplanation: Boolean(reason),
      affectedResources,
      affectedResourceCount: resourceCount,
      status: rec.status || 'pending_review',
    }
  })
}

export function countBySeverity(findings) {
  const counts = { high: 0, medium: 0, low: 0 }
  for (const f of Object.values(findings)) {
    const s = (f.severity || 'low').toLowerCase()
    if (counts[s] !== undefined) counts[s] += 1
  }
  return counts
}
