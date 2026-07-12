import type { Thesis } from "../models/Thesis";
import { authHeader, clearSession } from "./auth";

const API_URL = "http://localhost:8080/api/v1/theses";

async function handleResponse<T>(res: Response): Promise<T> {
    if (res.status === 401) {
        clearSession();
        throw new Error("Session expired, please log in again.");
    }
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
}

export async function getThesis(thesisId: string): Promise<Thesis> {
    const res = await fetch(`${API_URL}/${encodeURIComponent(thesisId)}`, {
        headers: { ...authHeader() }
    });
    return handleResponse<Thesis>(res);
}

export async function getAllTheses(): Promise<Thesis[]> {
    const res = await fetch(API_URL, {
        headers: { ...authHeader() }
    });
    const data = await handleResponse<Thesis[] | null>(res);
    return data ?? []; // handle null from empty ledger
}
