export interface SubmissionRequest {
    ThesisId: string;
    Grade: number;
    Document: File;
    Metadata: Record<string, unknown>;
}