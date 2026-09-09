import { useEffect, useRef, useState } from 'react'

import { getAwsRecommendations } from '../../api/client'

import { formatMoneyOrDash, formatPct, formatReasonCode } from '../../utils/format'

const SAVINGS_PLAN_LABELS = {
  COMPUTE_SP: 'Compute',
  SAGEMAKER_SP: 'SageMaker',
}

function savingsPlanLabel(planType) {
  return SAVINGS_PLAN_LABELS[planType] || planType || 'Unknown'
}

const PAYMENT_OPTION_LABELS = {
  NO_UPFRONT: 'no upfront',
  PARTIAL_UPFRONT: 'partial upfront',
  ALL_UPFRONT: 'all upfront',
}

// The lookback/term/payment-option note is derived from the first row
// rather than hardcoded, since these are parameters the backend passes
// to AWS on each request (aws_recommendations_service.py) -- if that
// ever changes, the UI note stays accurate without a separate edit.
function commitmentNote(rows, fallback) {
  const row = rows?.[0]

  if (!row) {
    return fallback
  }

  const parts = ['AWS Cost Explorer']

  if (row.lookback_period_days != null) {
    parts.push(`${row.lookback_period_days}-day lookback`)
  }

  if (row.term_years != null) {
    parts.push(`${row.term_years}-year`)
  }

  parts.push(
    PAYMENT_OPTION_LABELS[row.payment_option] ||
      (row.payment_option || 'no upfront').toLowerCase(),
  )

  return parts.join(' · ')
}

function EngineError({ children }) {
  return (
    <div className="aws-rec-engine-error">
      <span>!</span>
      {children}
    </div>
  )
}

function SavingsPlanRow({ row }) {
  return (
    <div className="aws-rec-row">
      <div className="aws-rec-row-main">
        <span className="aws-rec-tag">
          {savingsPlanLabel(row.plan_type)}{' '}
          Savings Plan
        </span>

        <div className="aws-rec-row-meta">
          Hourly commitment{' '}
          {formatMoneyOrDash(row.hourly_commitment)}
          /hr
          {' · '}
          {row.payment_option || 'No upfront'}
        </div>
      </div>

      <div className="aws-rec-row-savings mono">
        {formatMoneyOrDash(row.estimated_monthly_savings)}
        <small>
          {row.estimated_savings_pct != null
            ? `${formatPct(row.estimated_savings_pct)} saved`
            : '/mo'}
        </small>
      </div>
    </div>
  )
}

function ReservationRow({ row }) {
  return (
    <div className="aws-rec-row">
      <div className="aws-rec-row-main">
        <span className="aws-rec-tag">
          {row.service}
        </span>

        <div className="aws-rec-row-meta">
          {row.recommended_quantity}&times;{' '}
          {row.resource_type} reserved instance
          {row.recommended_quantity === 1 ? '' : 's'}
          {' · '}
          {row.payment_option || 'No upfront'}
        </div>
      </div>

      <div className="aws-rec-row-savings mono">
        {formatMoneyOrDash(
          row.estimated_monthly_savings,
        )}
        <small>/mo</small>
      </div>
    </div>
  )
}

function RightsizingRow({ row }) {
  const isTerminate =
    row.action === 'Terminate'

  return (
    <div className="aws-rec-row">
      <div className="aws-rec-row-main">
        <span
          className={`aws-rec-tag ${
            isTerminate
              ? 'aws-rec-tag-warn'
              : ''
          }`}
        >
          {isTerminate
            ? 'Termination candidate'
            : 'Resize'}
        </span>

        <div className="aws-rec-row-title">
          {row.resource_name ||
            row.resource_id ||
            'Unnamed EC2 instance'}
        </div>

        <div className="aws-rec-row-meta">
          {isTerminate ? (
            <>
              {row.current_instance_type ||
                'Unknown type'}
              {' · '}
              idle / underutilized
            </>
          ) : (
            <>
              {row.current_instance_type ||
                'Unknown'}
              {' → '}
              {row.target_instance_type ||
                'AWS target'}
            </>
          )}

          {row.max_cpu_utilization_pct !=
            null && (
            <>
              {' · '}
              peak CPU{' '}
              {formatPct(
                row.max_cpu_utilization_pct,
              )}
            </>
          )}

          {row.region && (
            <>
              {' · '}
              {row.region}
            </>
          )}
        </div>
      </div>

      <div className="aws-rec-row-savings mono">
        {formatMoneyOrDash(
          row.estimated_monthly_savings,
        )}
        <small>/mo</small>
      </div>
    </div>
  )
}

function ComputeOptimizerRow({ row }) {
  const isOverprovisioned =
    row.finding === 'Overprovisioned'

  const isUnderprovisioned =
    row.finding === 'Underprovisioned'

  const tagClass = isUnderprovisioned
    ? 'aws-rec-tag-warn'
    : ''

  return (
    <div className="aws-rec-row">
      <div className="aws-rec-row-main">
        <span
          className={`aws-rec-tag ${tagClass}`}
        >
          {row.finding ||
            'Not optimized'}
        </span>

        <div className="aws-rec-row-title">
          {row.resource_name ||
            row.resource_id ||
            'Unnamed EC2 instance'}
        </div>

        <div className="aws-rec-row-meta">
          {row.current_instance_type ||
            'Unknown'}
          {' → '}
          {row.recommended_instance_type ||
            'AWS recommendation'}

          {row.finding_reason_codes?.length >
            0 && (
            <>
              {' · '}
              {row.finding_reason_codes
                .slice(0, 2)
                .map(formatReasonCode)
                .join(', ')}
            </>
          )}
        </div>

        <div className="aws-rec-row-meta">
          {row.migration_effort && (
            <>
              Migration{' '}
              {row.migration_effort}
            </>
          )}

          {row.lookback_period_days !=
            null && (
            <>
              {' · '}
              {row.lookback_period_days}d
              lookback
            </>
          )}

          {row.estimated_savings_pct !=
            null && (
            <>
              {' · '}
              {formatPct(
                row.estimated_savings_pct,
              )}{' '}
              opportunity
            </>
          )}
        </div>
      </div>

      <div className="aws-rec-row-savings mono">
        {formatMoneyOrDash(
          row.estimated_monthly_savings,
        )}
        <small>
          {row.after_discounts_estimated_monthly_savings !=
          null
            ? '/mo, after discounts'
            : '/mo'}
        </small>
      </div>
    </div>
  )
}

function RecommendationGroup({
  title,
  note,
  rows,
  emptyText,
  Row,
  error,
}) {
  if (!error && !rows.length) {
    return (
      <div
        className="aws-rec-group-empty-row"
        title={emptyText}
      >
        <span className="aws-rec-group-empty-dot" />
        <strong>{title}</strong>
        <span>No opportunity found</span>
      </div>
    )
  }

  return (
    <div className="aws-rec-group">
      <div className="aws-rec-group-head">
        <div>
          <strong>{title}</strong>
          <span>{note}</span>
        </div>
      </div>

      {error ? (
        <EngineError>
          {error}
        </EngineError>
      ) : (
        rows.map((row, index) => (
          <Row
            key={
              row.resource_id
                ? `${row.resource_id}-${index}`
                : `${row.plan_type || row.service || 'row'}-${row.resource_type || ''}-${index}`
            }
            row={row}
          />
        ))
      )}
    </div>
  )
}

function EngineSummary({ data }) {
  const savings =
    data?.estimated_monthly_savings || {}

  const items = [
    {
      label: 'Savings Plans',
      value: savings.savings_plans,
      count: data?.savings_plans?.length ?? 0,
    },
    {
      label: 'Reserved Instances',
      value: savings.reservations,
      count: data?.reservations?.length ?? 0,
    },
    {
      label: 'Cost Explorer rightsizing',
      value:
        savings.cost_explorer_rightsizing,
      count:
        data?.rightsizing?.length ?? 0,
    },
    {
      label: 'Compute Optimizer',
      value: savings.compute_optimizer,
      count:
        data?.compute_optimizer?.length ?? 0,
    },
  ]

  return (
    <div className="aws-rec-summary">
      {items.map((item) => (
        <div
          className="aws-rec-summary-item"
          key={item.label}
        >
          <span>{item.label}</span>
          <strong className="mono">
            {formatMoneyOrDash(item.value)}
          </strong>
          <small>
            {item.count
              ? `${item.count} item${item.count === 1 ? '' : 's'} · /mo`
              : 'opportunity /mo'}
          </small>
        </div>
      ))}
    </div>
  )
}

export default function AwsRecommendationsPanel() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] =
    useState(false)
  const [error, setError] = useState(null)

  // Requests can resolve out of order (e.g. a slow initial load
  // resolving after a manual refresh) -- a request only gets to write
  // its result if it's still the most recently issued one.
  const requestIdRef = useRef(0)

  async function load(forceRefresh = false) {
    const requestId = ++requestIdRef.current

    if (forceRefresh) {
      setRefreshing(true)
    }

    setError(null)

    try {
      const response =
        await getAwsRecommendations({
          force_refresh: forceRefresh,
        })

      if (requestId === requestIdRef.current) {
        setData(response)
      }
    } catch (err) {
      if (requestId === requestIdRef.current) {
        setError(
          err?.message ||
            'Unable to load AWS recommendations.',
        )
      }
    } finally {
      if (requestId === requestIdRef.current) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }

  useEffect(() => {
    load(false)
  }, [])

  const isBusy = loading || refreshing

  const errors = data?.errors || []

  function engineError(engine) {
    const match = errors.find(
      (item) => item.engine === engine,
    )

    return match?.error || null
  }

  return (
    <section className="panel aws-recommendations-panel">
      <div className="panel-head">
        <div>
          <div className="eyebrow">
            / AWS Recommendations
          </div>

          <h2 className="panel-title">
            AWS-native recommendations
          </h2>

          <p className="panel-sub">
            Read-only, from AWS Cost Explorer and AWS
            Compute Optimizer — a separate source from
            CostLensAWS's own evidence-based findings.
          </p>
        </div>

        <div className="aws-rec-head-actions">
          {data?.retrieved_at && (
            <span className="snapshot-count">
              AWS snapshot
            </span>
          )}

          <button
            type="button"
            className="small-btn"
            onClick={() => load(true)}
            disabled={isBusy}
          >
            {refreshing
              ? 'Refreshing…'
              : '↻ Refresh'}
          </button>
        </div>
      </div>

      {error ? (
        <div className="page-error">
          {error}
        </div>
      ) : loading && !data ? (
        <div className="chart-empty">
          <span className="chart-empty-icon">
            &#9711;
          </span>

          <strong>
            Loading AWS recommendations&hellip;
          </strong>
        </div>
      ) : (
        <>
          <EngineSummary data={data} />

          <div className="aws-rec-groups">
            <RecommendationGroup
              title="Savings Plans"
              note={commitmentNote(
                data?.savings_plans,
                'AWS Cost Explorer',
              )}
              rows={data?.savings_plans || []}
              emptyText="No Savings Plan recommendation was returned by AWS."
              Row={SavingsPlanRow}
              error={engineError(
                'savings_plans',
              )}
            />

            <RecommendationGroup
              title="Reserved Instances"
              note={commitmentNote(
                data?.reservations,
                'AWS Cost Explorer',
              )}
              rows={data?.reservations || []}
              emptyText="No Reserved Instance recommendation was returned by AWS."
              Row={ReservationRow}
              error={engineError(
                'reservations',
              )}
            />

            <RecommendationGroup
              title="Cost Explorer Rightsizing"
              note="AWS Cost Explorer · EC2 same-family rightsizing"
              rows={data?.rightsizing || []}
              emptyText="No Cost Explorer EC2 rightsizing recommendation was returned by AWS."
              Row={RightsizingRow}
              error={engineError(
                'cost_explorer_rightsizing',
              )}
            />

            <RecommendationGroup
              title="Compute Optimizer"
              note="AWS Compute Optimizer · EC2 utilization and configuration analysis"
              rows={
                data?.compute_optimizer || []
              }
              emptyText="No Compute Optimizer EC2 opportunity was returned. AWS may still be analyzing the resources or there may be insufficient metric data."
              Row={ComputeOptimizerRow}
              error={engineError(
                'compute_optimizer',
              )}
            />
          </div>
        </>
      )}
    </section>
  )
}