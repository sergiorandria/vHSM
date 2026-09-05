export type UserRole = string;

export interface User {
  username: string;
  roles: UserRole[];
}

export interface SessionClaims {
  username: string;
  roles: UserRole[];
  exp: number;
}

export interface Thesis {
  thesisId: string;
  studentId: string;
  student?: {
    fullName: string;
    nationalId?: string;
    email: string;
    enrollmentYear: number;
    program: string;
    department: string;
  };
  administrative?: {
    institution: string;
    faculty: string;
    academicYear: string;
    supervisorName: string;
    juryMembers?: string[];
    defenseDate?: string;
    registrationDate: string;
  };
  metadata?: {
    title: string;
    abstract?: string;
    keywords?: string[];
    language: string;
    pageCount?: number;
    fileRef: string;
    fileChecksum?: string;
    submittedAt: string;
  };
  thesisGrade?: string;
  juryGrades?: Array<{
    jurorId: string;
    grade: number;
    comment?: string;
    submittedAt: string;
    submittedBy?: string;
  }>;
  pvSignatures?: Array<{
    jurorId: string;
    signature: string;
    signedAt: string;
  }>;
  status: 'DRAFT' | 'DEFENDED' | 'NOTARIZED' | 'ARCHIVED';
  createdBy?: string;
  createdAt?: string;
  updatedAt?: string;
  hashDocument?: string;
  signatureDocument?: string;
  hashPv?: string;
}

export interface JuryStatus {
  thesisId: string;
  status: string;
  required: number;
  gradesIn: number;
  pvSignaturesIn: number;
  pendingGraders?: string[];
  pendingSigners?: string[];
}

export interface NotificationItem {
  id: string;
  type: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  timestamp: number;
  source: string;
  actor: string;
  summary: string;
  detail?: Record<string, unknown>;
  thesisId?: string;
}

export interface SignatureProof {
  record_id: string;
  key_fingerprint: string;
  payload_digest: string;
  signature_b64: string;
  created_at: number;
  tx_id: string;
  block_number: number;
  submitter?: string;
}

export interface HistoryEntry {
  txId: string;
  timestamp: string;
  isDelete: boolean;
  value: Record<string, unknown>;
}
