import { useEffect, useState } from 'react'

import Nav from './components/Nav'
import DashboardTab from './components/DashboardTab'
import ScanPage from './components/ScanPage'
import ResultsPage from './components/ResultsPage'

import { useDashboard } from './hooks/useDashboard'
import { useScan } from './hooks/useScan'
import { useScanResults } from './hooks/useScanResults'
import { useDashboardScan } from './hooks/useDashboardScan'
import { getScans } from './api/client'

export default function App() {

  const routeToTab = (pathname) => (
    { '/analysis': 'analysis', '/results': 'results', '/overview': 'overview' }[pathname] || 'overview'
  )
  const [activeTab, setActiveTab] = useState(() => routeToTab(window.location.pathname))
  const [selectedScanId, setSelectedScanId] = useState(null)

  /*
   * Dashboard
   */
  const {
    dashboardData,
    loading: dashboardLoading,
    refreshing,
    error: dashboardError,
    loadDashboard,
    refreshCosts,
  } = useDashboard()

  /*
   * Dashboard current-month scan (quick action)
   */
  const {
    scanning: dashboardScanning,
    scanData: dashboardScanData,
    error: dashboardScanError,
    scanCurrentMonth,
  } = useDashboardScan({
    onCompleted: (scan) => {
      const scanId = scan?.id ?? scan?.scan_id
      if (scanId) {
        setSelectedScanId(scanId)
      }
      /*
       * Do not auto-navigate; the dashboard shows the persisted
       * completed scan panel and the user can click View Results.
       */
    },
  })

  /*
   * Scan (Analysis page)
   */
  const {
    scanData,
    loading: scanLoading,
    status: scanStatus,
    error: scanError,
    lastScanTime,
    runScan,
  } = useScan()

  /*
   * Results
   */
  const {
    resultsScan,
    findings,
    recommendations,
    loading: resultsLoading,
    error: resultsError,
    loadResults,
  } = useScanResults(selectedScanId)

  useEffect(() => {
    let active = true
    getScans()
      .then((scans) => {
        const latest = (Array.isArray(scans) ? scans : []).find((scan) =>
          ['completed', 'completed_with_errors'].includes(String(scan.status).toLowerCase()),
        )
        if (active && latest?.id) setSelectedScanId(latest.id)
      })
      .catch(() => {})
    return () => { active = false }
  }, [])

  /*
   * When scan completes, open results.
   */
  useEffect(() => {
    if (!scanData) return

    const status = String(
      scanData.status || ''
    ).toLowerCase()

    const scanId =
      scanData.scan_id ??
      scanData.id

    if (
      [
        'completed',
        'completed_with_errors',
      ].includes(status)
    ) {
      if (scanId) {
        setSelectedScanId(scanId)
      }

      handleTabChange('results')
    }
  }, [scanData])

  useEffect(() => {
    const onPopState = () => setActiveTab(routeToTab(window.location.pathname))
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  /*
   * Navigation
   */
  function handleTabChange(tab) {
    setActiveTab(tab)
    window.history.pushState({}, '', `/${tab}`)

    if (tab === 'results' && selectedScanId) {
      loadResults(selectedScanId)
    }
  }

  /*
   * Run analysis
   */
  async function handleRunAnalysis(config) {
    try {
      const scanId = await runScan(config)

      if (scanId) {
        setSelectedScanId(scanId)
      }

      /*
       * useScan handles polling.
       * When the scan becomes completed,
       * the useEffect above opens Results.
       */
    } catch (error) {
      console.error(
        'Failed to run cost analysis:',
        error
      )
    }
  }

  /*
   * Dashboard -> Analysis
   */
  function handleOpenAnalysis() {
    handleTabChange('analysis')
  }

  /*
   * Dashboard -> Results
   */
  function handleViewOptimization(scanId) {
    const resolvedId =
      scanId ??
      dashboardData?.optimization?.last_scan_id ??
      dashboardData?.latest_scan?.id ??
      dashboardData?.last_scan_id ??
      selectedScanId

    if (resolvedId) {
      setSelectedScanId(resolvedId)
    }

    handleTabChange('results')
  }

  /*
   * Scan -> Results
   */
  function handleViewResults(scanId) {
    if (scanId) {
      setSelectedScanId(scanId)
    }

    handleTabChange('results')
  }

  return (
    <div className="app">
      <Nav
        activeTab={activeTab}
        onTabChange={handleTabChange}
      />

      <main className="app-content">

        {activeTab === 'overview' && (
          <DashboardTab
            dashboardData={dashboardData}
            loading={dashboardLoading}
            refreshing={refreshing}
            error={dashboardError}
            onRunAnalysis={handleOpenAnalysis}
            onViewOptimization={handleViewOptimization}
            onRefreshCosts={refreshCosts}
            onFilterChange={loadDashboard}
            onScanCurrentMonth={scanCurrentMonth}
            scanning={dashboardScanning}
            scanData={dashboardScanData}
            scanError={dashboardScanError}
            lastScanId={selectedScanId}
          />
        )}

        {activeTab === 'analysis' && (
          <ScanPage
            scanData={scanData}
            loading={scanLoading}
            status={scanStatus}
            error={scanError}
            lastScanTime={lastScanTime}
            onRunAnalysis={handleRunAnalysis}
            onBack={() =>
              handleTabChange('overview')
            }
            onViewResults={handleViewResults}
          />
        )}

        {activeTab === 'results' && (
          <ResultsPage
            scanId={selectedScanId}
            scan={resultsScan}
            findings={findings}
            recommendations={recommendations}
            loading={resultsLoading}
            error={resultsError}
            onBack={() =>
              handleTabChange('overview')
            }
            onRunAnalysis={() =>
              handleTabChange('analysis')
            }
          />
        )}

      </main>
    </div>
  )
}