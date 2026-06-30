const API_URL = "http://localhost:8080/api/v1/submissions";
export async function submit(payload) {
    const response = await fetch(API_URL, {
        method: "POST",
        headers: {
            "Content-Type":"multipart/form-data"
        },
        body: JSON.stringify(payload)
    });
    if (!response.ok) {
        const errorMessage = await response.text();
        throw new Error(errorMessage);
    }
    const result = await response.json();
    return result;
}
