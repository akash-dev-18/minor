import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from '../lib/api'
import { uploadEmail } from '../lib/upload'
import type {
  AnalysisDetail,
  AnalysisFilters,
  AnalysisStats,
  ConfigResponse,
  HealthResponse,
  MLStatus,
  MlMetrics,
  ModuleInfo,
  PaginatedAnalyses,
  ReadinessResponse,
} from '../types/api'

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => api.get<HealthResponse>('/health'),
    refetchInterval: 30_000,
  })
}

export function useReadiness() {
  return useQuery({
    queryKey: ['ready'],
    queryFn: () => api.get<ReadinessResponse>('/ready'),
    refetchInterval: 30_000,
  })
}

export function useConfig() {
  return useQuery({
    queryKey: ['config'],
    queryFn: () => api.get<ConfigResponse>('/config'),
    staleTime: 5 * 60_000,
  })
}

export function useModules() {
  return useQuery({
    queryKey: ['modules'],
    queryFn: () => api.get<ModuleInfo[]>('/modules'),
    staleTime: 60_000,
  })
}

export function useMlStatus() {
  return useQuery({
    queryKey: ['ml', 'status'],
    queryFn: () => api.get<MLStatus>('/ml/status'),
    staleTime: 60_000,
  })
}

export function useMlMetrics() {
  return useQuery({
    queryKey: ['ml', 'metrics'],
    queryFn: () => api.get<MlMetrics>('/ml/metrics'),
    retry: false,
    staleTime: 60_000,
  })
}

export function analysesQueryKey(filters: AnalysisFilters) {
  return ['analyses', filters] as const
}

export function useAnalyses(filters: AnalysisFilters) {
  const params = new URLSearchParams()
  params.set('page', String(filters.page ?? 1))
  params.set('page_size', String(filters.pageSize ?? 20))
  if (filters.q) params.set('q', filters.q)
  if (filters.classification) params.set('classification', filters.classification)
  if (filters.riskLevel) params.set('risk_level', filters.riskLevel)
  params.set('sort', filters.sort ?? 'created_at')
  params.set('order', filters.order ?? 'desc')

  return useQuery({
    queryKey: analysesQueryKey(filters),
    queryFn: () => api.get<PaginatedAnalyses>(`/analyses?${params.toString()}`),
  })
}

export function useRecentAnalyses(limit = 5) {
  return useQuery({
    queryKey: ['analyses', 'recent', limit],
    queryFn: () => api.get<PaginatedAnalyses>(`/analyses?page=1&page_size=${limit}`),
    refetchInterval: 15_000,
  })
}

export function useAnalysis(id: string | undefined) {
  return useQuery({
    queryKey: ['analysis', id],
    queryFn: () => api.get<AnalysisDetail>(`/analyses/${id}`),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'PENDING' || status === 'RUNNING' ? 1_500 : false
    },
  })
}

export function useStats() {
  return useQuery({
    queryKey: ['analyses', 'stats'],
    queryFn: () => api.get<AnalysisStats>('/analyses/stats'),
    refetchInterval: 30_000,
  })
}

export function useUploadEmail() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: uploadEmail,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['analyses'] })
    },
  })
}

export function useDeleteAnalysis() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/analyses/${id}`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['analyses'] })
    },
  })
}
