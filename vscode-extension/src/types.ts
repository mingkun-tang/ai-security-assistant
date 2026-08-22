/** Shared finding types derived from CLI JSON. */

export type Confidence = "high" | "medium" | "low" | string;

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
  remediation?: string;
  aiExplanation?: string;
}

export interface ScanResult {
  findings: SecurityFinding[];
  filesAnalyzed?: number;
  project?: string;
}
