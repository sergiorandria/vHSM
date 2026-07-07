export interface ThesisMetadata {
    thesisTitle?: string;
    DefenseDate?: string;
    [key: string]: unknown;
}

export interface Thesis {
    thesisId: string;
    grade: number;
    hash?: string;
    signature?: string;
    metadata?: ThesisMetadata;
}
