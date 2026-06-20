import type { SubmissionRequest } from "../models/SubmissionRequest";
import type { SubmissionResponse } from "../models/SubmissionResponse";

const API_URL = "http://localhost:8080/api/v1/submissions";

export async function submit(
    payload: SubmissionRequest
): Promise<SubmissionResponse> {

    const response = await fetch(API_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

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