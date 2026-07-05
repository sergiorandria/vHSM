import type { SubmissionRequest } from "../models/SubmissionRequest";
import type { SubmissionResponse } from "../models/SubmissionResponse";
import { authHeader, clearSession } from "./auth";

const API_URL = "http://localhost:8080/api/v1/submissions";

export async function submit(
    payload: SubmissionRequest
): Promise<SubmissionResponse> {

    const formData = new FormData();

    formData.append("ThesisId", payload.ThesisId);
    formData.append("Grade", payload.Grade.toString());
    formData.append("Title", payload.Title);
    formData.append("Date", payload.Date);
    formData.append("Document", payload.Document);

    const response = await fetch(API_URL, {
        method: "POST",
        // Don't set Content-Type manually here — the browser needs to add
        // its own multipart boundary when sending a FormData body.
        headers: { ...authHeader() },
        body: formData
    });

    if (response.status === 401) {
        clearSession();
        throw new Error("Session expired, please log in again.");
    }

    if (!response.ok) {
        let errorMessage = await response.text();
        try {
            const jsonErr = JSON.parse(errorMessage);
            if (jsonErr.error) errorMessage = jsonErr.error;
        } catch (e) {
            // response not JSON; keep raw text
        }
        throw new Error(`HTTP ${response.status}: ${errorMessage}`);
    }

    const result: SubmissionResponse = await response.json();
    return result;
}
