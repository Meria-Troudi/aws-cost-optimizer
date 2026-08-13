import { useCallback, useState } from 'react'
import Nav from './components/Nav'
import DashboardTab from './components/DashboardTab'
import ScanTab from './components/ScanTab'
import ScanResults from './components/ScanResults'
import FindingsModal from './components/FindingsModal'
import RecommendationModal from './components/RecommendationModal'
import { useScan } from './hooks/useScan'
import { useDashboard } from './hooks/useDashboard'
import { useScanResults } from './hooks/useScanResults'
import { mapApiFinding, mapApiRecommendations } from './data/findings'

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard-tab')
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [selectedRecommendation, setSelectedRecommendation] = useState(null)

  const { scanData, loading, status, error, lastScanTime, runScan } = useScan()

  const { dashboardData, loading: dashboardLoading, error: dashboardError, loadDashboard, refreshCosts, refreshing } =
    useDashboard()

  const lastScanId = dashboardData?.optimization?.last_scan_id

  const {
    resultsScan,
    findings,
    recommendations,
    loading: resultsLoading,
    error: resultsError,
    loadResults,
    hasResults,
  } = useScanResults(lastScanId)

  const presentedRecs = mapApiRecommendations(recommendations || [], findings)

  const showTab = useCallback((tabId) => {
    setActiveTab(tabId)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])

  const handleViewOptimization = useCallback(() => {
    loadResults(lastScanId)
    showTab('results-tab')
  }, [lastScanId, loadResults, showTab])

  async function handleAnalysis(form) {
    try {
      const scanId = await runScan(form)
      await loadDashboard()
      await loadResults(scanId)
      showTab('results-tab')
    } catch {
      await loadDashboard()
    }
  }

  function openRecommendation(rec) {
    setSelectedRecommendation(rec)
  }

  function relatedFindingForRec(rec) {
    if (rec?.linkedFindingId && findings[rec.linkedFindingId]) {
      return findings[rec.linkedFindingId]
    }
    if (rec?.finding_id && findings[String(rec.finding_id)]) {
      return findings[String(rec.finding_id)]
    }
    return null
  }

  return (
    <div className="shell">
      <Nav activeTab={activeTab} onTabChange={showTab} />

      <section
        id="dashboard-tab"
        className={`app-panel ${activeTab === 'dashboard-tab' ? 'active' : ''}`}
      >
        <DashboardTab
          dashboardData={dashboardData}
          loading={dashboardLoading}
          refreshing={refreshing}
          error={dashboardError}
          onRunAnalysis={() => showTab('analysis-tab')}
          onViewOptimization={handleViewOptimization}
          onRefreshCosts={refreshCosts}
        />
      </section>

      <section
        id="analysis-tab"
        className={`app-panel ${activeTab === 'analysis-tab' ? 'active' : ''}`}
      >
        <ScanTab
          onScan={handleAnalysis}
          loading={loading}
          status={status}
          error={error}
          lastScanTime={lastScanTime}
          scanData={scanData}
          account={dashboardData?.account}
          collectionStatus={dashboardData?.collection_coverage || dashboardData?.collection_status}
          onBackToDashboard={() => showTab('dashboard-tab')}
        />
      </section>

      <section
        id="results-tab"
        className={`app-panel ${activeTab === 'results-tab' ? 'active' : ''}`}
      >
        <ScanResults
          scanData={resultsScan}
          findings={findings}
          recommendations={presentedRecs}
          loading={resultsLoading}
          error={resultsError}
          hasResults={hasResults}
          latestAttempt={scanData}
          onFindingClick={setSelectedFinding}
          onRecommendationClick={openRecommendation}
          onBackToDashboard={() => showTab('dashboard-tab')}
        />
      </section>

      <footer>
        <span>COSTLENS · AWS COST OPTIMIZATION</span>
        <span>DATA: SQLITE · FASTAPI · COST EXPLORER</span>
      </footer>

      <FindingsModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />

      <RecommendationModal
        recommendation={selectedRecommendation}
        relatedFinding={relatedFindingForRec(selectedRecommendation)}
        onClose={() => setSelectedRecommendation(null)}
        onViewFinding={() => {
          const related = relatedFindingForRec(selectedRecommendation)
          if (related) {
            setSelectedRecommendation(null)
            setSelectedFinding(related)
          }
        }}
      />
    </div>
  )
}
