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
        const errorMessage = await response.text();
        throw new Error(errorMessage);
    }

    const result: SubmissionResponse = await response.json();

    return result;
}