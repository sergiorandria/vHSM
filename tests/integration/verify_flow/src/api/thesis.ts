// api/theses.ts
import type { Thesis } from "../models/Thesis";

const API_URL = "http://localhost:8080/api/v1/theses";

export async function getThesis(thesisId: string): Promise<Thesis> {
    const res = await fetch(`${API_URL}/${encodeURIComponent(thesisId)}`);
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
}

export async function getAllTheses(): Promise<Thesis[]> {
    const res = await fetch(API_URL);
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    return data ?? []; // handle null from empty ledger
}