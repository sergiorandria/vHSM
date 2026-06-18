export interface SubmissionRequest {
    thesisId: string;
    grade: number;
    metadata: Record<string, unknown>;
}