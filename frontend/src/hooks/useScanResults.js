import { useCallback, useEffect, useState } from 'react'
import {
  getFindings,
  getRecommendations,
  getScan,
  getScanCostSummary,
} from '../api/client'
import { mapApiFindings, mapApiRecommendations } from '../data/findings'

function isDisplayableScan(data) {
  if (!data) return false

  return (
    data.status === 'completed' ||
    data.status === 'completed_with_errors' ||
    Number(data.findings_count || 0) > 0 ||
    Number(data.recommendations_count || 0) > 0
  )
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : []
}

export function useScanResults(lastScanId = null) {
  const [resultsScan, setResultsScan] = useState(null)
  const [findings, setFindings] = useState({})
  const [recommendations, setRecommendations] = useState([])
  const [costSummary, setCostSummary] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const loadResults = useCallback(async (scanId = null) => {
    const id = scanId ?? lastScanId

    if (!id) {
      setResultsScan(null)
      setFindings({})
      setRecommendations([])
      setCostSummary(null)
      setError(null)
      return null
    }

    setLoading(true)
    setError(null)

    try {
      const scan = await getScan(id)

      if (!scan) {
        throw new Error('Scan not found.')
      }

      /*
       * A running scan is not a results page yet.
       * Keep the scan metadata so the UI can display its status.
       */
      if (!isDisplayableScan(scan)) {
        setResultsScan(scan)
        setFindings({})
        setRecommendations([])
        return scan
      }

      const [apiFindings, apiRecommendations, summary] = await Promise.all([
        getFindings(id),
        getRecommendations(id),
        getScanCostSummary(id),
      ])

      const safeFindings = normalizeArray(apiFindings)
      const safeRecommendations = normalizeArray(apiRecommendations)

      const mappedFindings = mapApiFindings(
        safeFindings,
        scan.region,
      )

      const mappedRecommendations = mapApiRecommendations(
        safeRecommendations,
        mappedFindings,
      )

      setResultsScan(scan)
      setFindings(mappedFindings)
      setRecommendations(mappedRecommendations)
      setCostSummary(summary)

      return scan
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : 'Failed to load scan results.'

      setError(message)

      /*
       * Do not destroy already-loaded results if a refresh fails.
       * This prevents the page from becoming blank because of one
       * failed API request.
       */
      return null
    } finally {
      setLoading(false)
    }
  }, [lastScanId])

  useEffect(() => {
    if (lastScanId == null || lastScanId === '') {
      setResultsScan(null)
      setFindings({})
      setRecommendations([])
      setCostSummary(null)
      setError(null)
      return
    }

    loadResults(lastScanId)
  }, [lastScanId, loadResults])

  const clearResults = useCallback(() => {
    setResultsScan(null)
    setFindings({})
    setRecommendations([])
    setCostSummary(null)
    setError(null)
  }, [])

  return {
    resultsScan,
    findings,
    recommendations,
    costSummary,
    loading,
    error,
    loadResults,
    clearResults,
    hasResults: isDisplayableScan(resultsScan),
  }
}

export default useScanResults
