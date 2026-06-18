import { Student } from "../models/Student";

const API_URL = "http://localhost:8080/api/students";

export async function sendJSON(
    student: Student
): Promise<void> {

    const response = await fetch(API_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(student)
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
}