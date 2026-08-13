import { useCallback, useEffect, useState } from 'react'
import { getFindings, getRecommendations, getScan } from '../api/client'
import { mapApiFindings } from '../data/findings'

function isDisplayableScan(data) {
  if (!data) return false
  if (data.status === 'completed' || data.status === 'completed_with_errors') return true
  return (data.findings_count ?? 0) > 0 || (data.recommendations_count ?? 0) > 0
}

export function useScanResults(lastScanId) {
  const [resultsScan, setResultsScan] = useState(null)
  const [findings, setFindings] = useState({})
  const [recommendations, setRecommendations] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const loadResults = useCallback(async (scanId) => {
    const id = scanId ?? lastScanId
    if (!id) {
      setResultsScan(null)
      setFindings({})
      setRecommendations([])
      return
    }

    setLoading(true)
    setError(null)

    try {
      const data = await getScan(id)

      if (!isDisplayableScan(data)) {
        setResultsScan(null)
        setFindings({})
        setRecommendations([])
        return
      }

      const [apiFindings, apiRecommendations] = await Promise.all([
        getFindings(id),
        getRecommendations(id),
      ])

      setResultsScan(data)
      setFindings(mapApiFindings(apiFindings, data.region))
      setRecommendations(apiRecommendations)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [lastScanId])

  useEffect(() => {
    loadResults(lastScanId)
  }, [lastScanId, loadResults])

  return {
    resultsScan,
    findings,
    recommendations,
    loading,
    error,
    loadResults,
    hasResults: isDisplayableScan(resultsScan),
  }
}
