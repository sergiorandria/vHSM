export interface SubmissionResponse {
    thesisId: string;
    docHash: string;
    signature: string;
    canonicalJson: string;
    receivedAt: string;
}