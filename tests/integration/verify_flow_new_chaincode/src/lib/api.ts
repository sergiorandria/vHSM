import { useAuth } from './auth';

export const API_BASE = 'http://localhost:8080/api/v1';

// Talks only to the Go gateway API, which is the sole thing that speaks to
// the Fabric ledger. The browser never touches chaincode directly.
export const useApi = () => {
  const { token, logout } = useAuth();

  const fetchApi = async (endpoint: string, options: RequestInit = {}) => {
    const headers = new Headers(options.headers || {});
    if (token) headers.set('Authorization', `Bearer ${token}`);

    const response = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
    if (response.status === 401) {
      logout();
      throw new Error('Session expired');
    }
    return response;
  };

  return fetchApi;
};

// One jury member's grade for a thesis — mirrors chaincode.go's JuryGrade.
export interface JuryGrade {
  jurorId: string;
  grade: number;
  comment?: string;
  submittedAt: string;
}

// One jury member's signature over the shared PV hash — mirrors
// chaincode.go's PvSignature.
export interface PvSignature {
  jurorId: string;
  signature: string;
  signedAt: string;
}

export interface Thesis {
  thesisId: string;
  studentId?: string;
  student?: {
    fullName: string;
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
    // Assigned jury for this thesis. The thesis only moves DRAFT ->
    // DEFENDED once every one of these IDs has a matching entry in
    // juryGrades (see chaincode.go's SubmitJuryGrade).
    juryMembers?: string[];
    defenseDate: string;
    registrationDate: string;
  };
  metadata?: {
    title: string;
    language: string;
    submittedAt: string;
  };
  // Final grade, only populated once every jury member has graded.
  grade?: string;
  // One entry per jury member who has graded so far — never a substitute
  // for `grade`, which is only set once this array is complete.
  juryGrades?: JuryGrade[];
  // One entry per jury member who has signed the PV so far.
  pvSignatures?: PvSignature[];
  status: 'DRAFT' | 'DEFENDED' | 'NOTARIZED' | 'ARCHIVED';
  hashDocument?: string;
  hashPv?: string;
}

// Grading/signing progress for a thesis — mirrors chaincode.go's
// JuryStatus, returned by GET /theses/:thesisId/jury-status.
export interface JuryStatusInfo {
  thesisId: string;
  status: Thesis['status'];
  required: number;
  gradesIn: number;
  pvSignaturesIn: number;
  pendingGraders?: string[];
  pendingSigners?: string[];
}
