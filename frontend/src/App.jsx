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
import { isDoneStatus } from './utils/scanStatus'

export default function App() {


  const routeToTab = (pathname) => (
    { '/analysis': 'analysis', '/results': 'results', '/overview': 'overview' }[pathname] || 'overview'
  )
  const [activeTab, setActiveTab] = useState(() => routeToTab(window.location.pathname))
  const [selectedScanId, setSelectedScanId] = useState(null)

  const {
    dashboardData,
    loading: dashboardLoading,
    refreshing,
    error: dashboardError,
    loadDashboard,
    refreshCosts,
  } = useDashboard()

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
    },
  })

  const {
    scanData,
    loading: scanLoading,
    status: scanStatus,
    error: scanError,
    lastScanTime,
    runScan,
  } = useScan()

  const {
    resultsScan,
    findings,
    recommendations,
    costSummary,
    costDrivers,
    collectionSummary,
    collectionSummaryLoading,
    collectionSummaryError,
    loadCollectionSummary,
    loading: resultsLoading,
    error: resultsError,
    loadResults,
    hasResults,
  } = useScanResults(
    selectedScanId,
  )

  useEffect(() => {
    let active = true
    getScans()
      .then((scans) => {
        const latest = (Array.isArray(scans) ? scans : []).find((scan) =>
          isDoneStatus(scan.status),
        )
        if (active && latest?.id) setSelectedScanId(latest.id)
      })
      .catch((err) => {
        // Preselecting the most recent scan is best-effort, but a
        // silent catch made an unreachable backend indistinguishable
        // from "no scans yet". Log it so the failure is diagnosable.
        console.error('Could not load the scan list:', err)
      })
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (!scanData) return

    const scanId =
      scanData.scan_id ??
      scanData.id

    if (isDoneStatus(scanData.status)) {
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

  function handleTabChange(tab) {
    setActiveTab(tab)
    window.history.pushState({}, '', `/${tab}`)

    if (tab === 'results' && selectedScanId) {
      loadResults(selectedScanId)
    }
  }

  async function handleRunAnalysis(config) {
    try {
      const scanId = await runScan(config)

      if (scanId) {
        setSelectedScanId(scanId)
      }
    } catch (error) {
      console.error(
        'Failed to run cost analysis:',
        error
      )
    }
  }

  function handleOpenAnalysis() {
    handleTabChange('analysis')
  }

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
            costSummary={costSummary}
            costDrivers={costDrivers}
            collectionSummary={collectionSummary}
            collectionSummaryLoading={collectionSummaryLoading}
            collectionSummaryError={collectionSummaryError}
            onLoadCollectionSummary={loadCollectionSummary}
            hasResults={hasResults}
            loading={resultsLoading}
            error={resultsError}
            onRefresh={() =>
              loadResults(selectedScanId)
            }
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