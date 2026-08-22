/** Shared finding types derived from CLI JSON. */

export type Confidence = "high" | "medium" | "low" | string;

export interface EvidenceLocation {
  id?: string;
  kind: string;
  attrs: Record<string, unknown>;
  notes?: string[];
  location?: {
    path?: string;
    line?: number | null;
    column?: number | null;
    snippet?: string;
  };
}

export interface EvidenceStep {
  label: string;
  kind: string;
  snippet?: string;
  file?: string;
  line?: number | null;
}

export interface SecurityFinding {
  id: string;
  issueType: string;
  displayName: string;
  confidence: Confidence;
  file: string;
  line: number | null;
  column: number | null;
  snippet?: string;
  explanation: string;
  impact?: string;
  brokenTrust?: string;
  remediation?: string;
  recommendations: string[];
  evidenceLocations: EvidenceLocation[];
  evidenceSteps: EvidenceStep[];
  aiExplanation?: string;
}

export interface ScanResult {
  findings: SecurityFinding[];
  filesAnalyzed?: number;
  project?: string;
}

export interface FindingDetailModel {
  issue: string;
  confidence: string;
  confidenceLabel: string;
  file: string;
  line: number | null;
  evidenceSteps: EvidenceStep[];
  whyFlagged: string;
  impact: string;
  primaryRemediation?: string;
  additionalRemediations: string[];
  aiExplanation?: string;
  showAiSection: boolean;
  aiDisclaimer: string;
}
