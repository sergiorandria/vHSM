// models/Thesis.ts
export interface ThesisMetadata {
    thesisTitle: string;
    DefenseDate: string; // matches chaincode's exact JSON tag casing
}

export interface Thesis {
    thesisId: string;
    grade: number;
    metadata: ThesisMetadata;
    hash: string;
    signature: string;
}