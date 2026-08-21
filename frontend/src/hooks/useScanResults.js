import { useCallback, useEffect, useState } from 'react'
import {
  getFindings,
  getRecommendations,
  getScan,
  getScanCostSummary,
  getScanCostDrivers,
  getScanCollectionSummary,
} from '../api/client'
import { mapApiFindings, mapApiRecommendations } from '../mappers/findings'

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
  const [costDrivers, setCostDrivers] = useState([])
  const [collectionSummary, setCollectionSummary] = useState(null)
  const [collectionSummaryLoading, setCollectionSummaryLoading] = useState(false)
  const [collectionSummaryError, setCollectionSummaryError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const loadResults = useCallback(async (scanId = null) => {
    const id = scanId ?? lastScanId

    if (!id) {
      setResultsScan(null)
      setFindings({})
      setRecommendations([])
      setCostSummary(null)
      setCostDrivers([])
      setCollectionSummary(null)
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

      if (!isDisplayableScan(scan)) {
        setResultsScan(scan)
        setFindings({})
        setRecommendations([])
        return scan
      }

      const [apiFindings, apiRecommendations, summary, drivers] = await Promise.all([
        getFindings(id),
        getRecommendations(id),
        getScanCostSummary(id),
        getScanCostDrivers(id),
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
      setCostDrivers(normalizeArray(drivers?.drivers))

      return scan
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : 'Failed to load scan results.'

      setError(message)

      return null
    } finally {
      setLoading(false)
    }
  }, [lastScanId])

  const loadCollectionSummary = useCallback(async (scanId = null) => {
    const id = scanId ?? lastScanId

    if (!id) return null

    setCollectionSummaryLoading(true)
    setCollectionSummaryError(null)

    try {
      const data = await getScanCollectionSummary(id)
      setCollectionSummary(data)
      return data
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : 'Failed to load collection summary.'

      setCollectionSummaryError(message)
      return null
    } finally {
      setCollectionSummaryLoading(false)
    }
  }, [lastScanId])

  useEffect(() => {
    if (lastScanId == null || lastScanId === '') {
      setResultsScan(null)
      setFindings({})
      setRecommendations([])
      setCostSummary(null)
      setCostDrivers([])
      setCollectionSummary(null)
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
    setCostDrivers([])
    setCollectionSummary(null)
    setError(null)
  }, [])

  return {
    resultsScan,
    findings,
    recommendations,
    costSummary,
    costDrivers,
    collectionSummary,
    collectionSummaryLoading,
    collectionSummaryError,
    loadCollectionSummary,
    loading,
    error,
    loadResults,
    clearResults,
    hasResults: isDisplayableScan(resultsScan),
  }
}

export default useScanResults
