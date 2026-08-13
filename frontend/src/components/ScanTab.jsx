import { useEffect, useState } from 'react'
import { getCostRegions } from '../api/client'

const STATUS_CHIP = {
  idle: { className: 'status-chip status-idle', label: 'Idle' },
  running: { className: 'status-chip status-running', label: 'Analyzing…' },
  done: { className: 'status-chip status-done', label: 'Completed' },
}

function daysBetween(start, end) {
  const ms = new Date(end) - new Date(start)
  return Math.max(1, Math.round(ms / (1000 * 60 * 60 * 24)))
}

function formatDateInput(date) {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

function defaultDateRange() {
  const end = new Date()
  const start = new Date()
  start.setMonth(start.getMonth() - 3)
  return {
    start_date: formatDateInput(start),
    end_date: formatDateInput(end),
  }
}

export default function ScanTab({
  onScan,
  loading,
  status,
  error,
  lastScanTime,
  scanData,
  account,
  collectionStatus,
  onBackToDashboard,
}) {
  const [regions, setRegions] = useState([])
  const [form, setForm] = useState(() => {
    const { start_date, end_date } = defaultDateRange()
    return {
      start_date,
      end_date,
      region: '',
      cost_threshold: 200,
    }
  })

  useEffect(() => {
    getCostRegions()
      .then((data) => setRegions(data.regions || []))
      .catch(() => setRegions([]))
  }, [])

  function handleChange(e) {
    const { name, value } = e.target
    const key =
      name === 'scan-start-date'
        ? 'start_date'
        : name === 'scan-end-date'
          ? 'end_date'
          : name === 'scan-region'
            ? 'region'
            : name === 'scan-cost-threshold'
              ? 'cost_threshold'
              : null
    if (key) {
      setForm((prev) => ({
        ...prev,
        [key]: key === 'cost_threshold' ? Number(value) : value,
      }))
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (form.start_date > form.end_date) return
    const payload = {
      ...form,
      region: form.region || null,
    }
    try {
      await onScan(payload)
    } catch {
      // error shown via prop
    }
  }

  const chip = STATUS_CHIP[status] || STATUS_CHIP.idle
  const windowDays = daysBetween(form.start_date, form.end_date)
  const dateError =
    form.start_date && form.end_date && form.start_date > form.end_date
      ? 'Start date must be before end date.'
      : null
  const regionLabel = form.region || 'All regions'
  const displayAccount = account?.display_name || 'AWS Account'
  const accountDetail = account?.account_id_masked
    ? `Account ${account.account_id_masked} · ${account.connection_label || 'Connected'}`
    : account?.connection_label || 'Connected via AWS configuration'

  return (
    <>
      <div className="dashboard-head">
        <div className="headline">
          <h1>
            Cost Analysis
            <br />
            
          </h1>
          <div className="sub">
            Configure the period and scope for the optimization analysis engine. Cost monitoring
            data is collected separately on Overview.
          </div>
        </div>
      </div>

      <div className="scan-layout">
        <form className="scan-card" onSubmit={handleSubmit} autoComplete="off">
          <h2>Analysis configuration</h2>

          <div className="scan-section-label">Analysis period</div>
          <div className="credential-grid">
            <div className="field">
              <label htmlFor="scan-start-date">Start date</label>
              <input
                type="date"
                id="scan-start-date"
                name="scan-start-date"
                autoComplete="off"
                value={form.start_date}
                onChange={handleChange}
                required
              />
            </div>
            <div className="field">
              <label htmlFor="scan-end-date">End date</label>
              <input
                type="date"
                id="scan-end-date"
                name="scan-end-date"
                autoComplete="off"
                value={form.end_date}
                onChange={handleChange}
                required
              />
            </div>
          </div>

          <div className="scan-section-label">Scope</div>
          <div className="credential-grid">
            <div className="field">
              <label htmlFor="scan-region">Region</label>
              <select
                id="scan-region"
                name="scan-region"
                autoComplete="off"
                value={form.region}
                onChange={handleChange}
              >
                <option value="">All regions</option>
                {regions.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="scan-cost-threshold">Minimum cost driver</label>
              <input
                type="number"
                id="scan-cost-threshold"
                name="scan-cost-threshold"
                autoComplete="off"
                value={form.cost_threshold}
                onChange={handleChange}
                min="0"
                step="10"
                required
              />
              <div className="field-hint">
                Only cost drivers ≥ ${form.cost_threshold} trigger detailed resource discovery
                and evidence collection.
              </div>
            </div>
          </div>

          {dateError && <div className="page-error">{dateError}</div>}
          {error && !dateError && <div className="page-error">{error}</div>}

          {loading && (
            <div className="scan-progress">
              <div className="scan-progress-bar">
                <div className="scan-progress-fill" />
              </div>
              <div className="scan-progress-label">Analyzing AWS environment…</div>
            </div>
          )}

          <div className="scan-actions">
            <button
              type="submit"
              className={`btn-scan ${loading ? 'loading' : ''}`}
              disabled={loading || Boolean(dateError)}
            >
              <span className="spinner" />
              <span>{loading ? 'Analyzing…' : '▶ Run Cost Analysis'}</span>
            </button>
          </div>

          <div className="scan-status-large">
            <div>
              <div className="scan-status-label">Last analysis</div>
              <div className="scan-status-value">{lastScanTime}</div>
            </div>
            <span className={chip.className}>
              <span className="d" />
              {chip.label}
            </span>
          </div>
        </form>

        <div className="scan-summary">
          <div className="scan-section-label">Analysis scope</div>
          <div className="scan-stat">
            <div className="k">AWS account</div>
            <div className="v">{displayAccount}</div>
            <div className="field-hint">{accountDetail}</div>
          </div>
          <div className="scan-stat">
            <div className="k">Regions discovered</div>
            <div className="v mono">{regions.length || collectionStatus?.items?.find((i) => i.key === 'regions')?.count || '—'}</div>
          </div>
          <div className="scan-stat">
            <div className="k">Region scope</div>
            <div className="v mono">{regionLabel}</div>
          </div>
          <div className="scan-stat">
            <div className="k">Analysis window</div>
            <div className="v mono">{windowDays} days</div>
          </div>
          <div className="scan-stat">
            <div className="k">Cost threshold</div>
            <div className="v mono">${form.cost_threshold}</div>
          </div>
          <div className="scan-stat">
            <div className="k">Latest analysis</div>
            <div className="v">
              {scanData?.scan_id ? `#${scanData.scan_id} · ${scanData.status}` : 'No analysis yet'}
            </div>
          </div>
          <button type="button" className="small-btn" onClick={onBackToDashboard}>
            ← Back to Overview
          </button>
        </div>
      </div>
    </>
  )
}
