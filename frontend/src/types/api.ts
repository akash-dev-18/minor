export type AnalysisStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'SKIPPED'
  | 'UNAVAILABLE'

export type Classification = 'LEGITIMATE' | 'SPAM' | 'PHISHING'
export type RiskLevel = 'LOW' | 'GUARDED' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'

export interface HealthResponse {
  status: 'ok' | 'degraded'
  version: string
  database: 'ok' | 'unavailable'
  timestamp: string
}

export interface ReadinessResponse {
  ready: boolean
  checks: Record<string, boolean>
}

export type ModuleName =
  | 'email_parser'
  | 'url_analysis'
  | 'domain_reputation'
  | 'header_analysis'
  | 'content_analysis'
  | 'attachment_analysis'
  | 'ml_classification'

export interface IntegrationAvailability {
  url_fetch: boolean
  dns_lookups: boolean
  rdap: boolean
  virustotal: boolean
  safe_browsing: boolean
  abuseipdb: boolean
  clamav: boolean
}

export interface ConfigResponse {
  app_name: string
  app_env: string
  version: string
  max_upload_bytes: number
  max_attachment_bytes: number
  retention_days: number
  module_timeout_seconds: number
  ml_available: boolean
  integrations: IntegrationAvailability
}

export interface ModuleInfo {
  name: ModuleName
  title: string
  description: string
  available: boolean
  reason: string | null
}

export interface Finding {
  type: string
  title: string
  severity: Severity
  description: string
  evidence: string | null
  recommendation: string | null
  confidence: number | null
  risk_contribution: number | null
  source_module: ModuleName
  metadata: Record<string, unknown>
}

export interface AnalysisSummary {
  id: string
  original_filename: string
  sender: string | null
  subject: string | null
  classification: Classification | null
  risk_score: number | null
  risk_level: RiskLevel | null
  status: AnalysisStatus
  created_at: string
  completed_at: string | null
}

export interface PaginatedAnalyses {
  items: AnalysisSummary[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface AnalysisModuleResult {
  id: string
  module_name: ModuleName
  execution_status: AnalysisStatus
  execution_duration: number | null
  error_message: string | null
  result: Record<string, unknown> | null
}

export interface AuthenticationResults {
  spf: string
  dkim: string
  dmarc: string
}

export interface RiskContribution {
  category: string
  finding_type: string
  title: string
  severity: Severity
  module: ModuleName
  contribution: number
  raw_contribution: number
  evidence: string | null
  suppressed_duplicates: number
}

export interface UnknownCheck {
  module: ModuleName
  status: AnalysisStatus
  reason: string
}

export interface MlPrediction {
  label: Classification
  confidence: number
  contribution: number
  model_version: string | null
}

export interface AnalysisDetail extends AnalysisSummary {
  modules: AnalysisModuleResult[]
  findings: Finding[]
  authentication: AuthenticationResults | null
  recommendations: string[]
  explanation: string | null
  positives: string[]
  unknowns: UnknownCheck[]
  contributions: RiskContribution[]
  ml_prediction: MlPrediction | null
  assessment_confidence: number | null
  error_message: string | null
}

export interface AnalysisStats {
  total: number
  threats: number
  last_24_hours: number
  average_risk_score: number | null
  by_classification: Record<Classification, number>
  by_risk_level: Record<RiskLevel, number>
}

export interface AnalysisSubmission {
  analysis_id: string
  status: AnalysisStatus
  message: string
}

export interface AnalysisFilters {
  page?: number
  pageSize?: number
  q?: string
  classification?: Classification | ''
  riskLevel?: RiskLevel | ''
  sort?: 'created_at' | 'risk_score'
  order?: 'asc' | 'desc'
}

export interface MLStatus {
  available: boolean
  model_name: string | null
  model_version: string | null
  algorithm: string | null
  trained_at: string | null
  reason: string | null
}

export interface MlClassMetrics {
  precision: number
  recall: number
  f1: number
  support: number
}

export interface MlEvaluation {
  accuracy: number
  macro_precision?: number
  macro_recall?: number
  macro_f1?: number
  phishing_precision?: number
  phishing_recall?: number
  phishing_f1?: number
  per_class?: Record<Classification, MlClassMetrics>
  confusion_matrix?: number[][]
  labels?: Classification[]
}

export interface MlMetrics {
  model_version: string
  algorithm: string
  evaluated_at: string
  test: MlEvaluation
  validation?: Record<string, MlEvaluation>
  cross_validation?: {
    folds: number
    results: Record<string, MlEvaluation>
  }
  selection?: { metric_order: string[]; selected: string }
  diagnostics?: {
    calibration?: {
      expected_calibration_error: number
      mean_confidence: number
      accuracy: number
      bins: number
    }
    by_source?: Record<
      string,
      {
        records: number
        accuracy: number
        labels: Record<Classification, number>
        predicted: Record<Classification, number>
        [key: string]: unknown
      }
    >
    notes?: string[]
  }
}

export interface ApiErrorBody {
  error: {
    code: string
    message: string
    details: Record<string, unknown> | null
  }
}
