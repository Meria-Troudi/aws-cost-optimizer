import { useCallback, useEffect, useRef, useState } from 'react'
import { getDashboard, refreshCostData } from '../api/client'

export function useDashboard() {
  const [dashboardData, setDashboardData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState(null)
  const autoRefreshAttempted = useRef(false)

  const loadDashboard = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getDashboard()
      setDashboardData(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const refreshCosts = useCallback(async () => {
    setRefreshing(true)
    setError(null)
    try {
      await refreshCostData({})
      await loadDashboard()
    } catch (err) {
      setError(err.message)
    } finally {
      setRefreshing(false)
    }
  }, [loadDashboard])

  useEffect(() => {
    loadDashboard()
  }, [loadDashboard])

  useEffect(() => {
    if (autoRefreshAttempted.current) return
    if (loading || refreshing || dashboardData?.cost_available) return
    autoRefreshAttempted.current = true
    refreshCosts()
  }, [loading, refreshing, dashboardData?.cost_available, refreshCosts])

  return {
    dashboardData,
    loading,
    refreshing,
    error,
    loadDashboard,
    refreshCosts,
  }
}
