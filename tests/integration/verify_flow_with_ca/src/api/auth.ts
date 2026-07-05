import type { LoginResponse } from "../models/LoginResponse";

const API_URL = "http://localhost:8080/api/v1/login";
const SESSION_KEY = "thesis_session";

export interface StoredSession {
    token: string;
    username: string;
    roles: string[];
    expiresAt: number; // epoch ms
}

export async function login(username: string, password: string): Promise<StoredSession> {
    const res = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data: LoginResponse = await res.json();
    const session: StoredSession = {
        token: data.token,
        username: data.username,
        roles: data.roles,
        expiresAt: Date.now() + data.expires_in * 1000
    };

    // sessionStorage: cleared when the tab closes, avoids leaving a live
    // token sitting around indefinitely on a shared machine.
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
    return session;
}

export function getSession(): StoredSession | null {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;

    try {
        const session: StoredSession = JSON.parse(raw);
        if (Date.now() >= session.expiresAt) {
            clearSession();
            return null;
        }
        return session;
    } catch {
        clearSession();
        return null;
    }
}

export function clearSession(): void {
    sessionStorage.removeItem(SESSION_KEY);
}

export function authHeader(): Record<string, string> {
    const session = getSession();
    return session ? { Authorization: `Bearer ${session.token}` } : {};
}
