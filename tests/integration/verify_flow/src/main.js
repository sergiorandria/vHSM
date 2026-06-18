import { submit } from "./api/submissions";
document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("studentForm");
    if (!form) {
        console.error("studentForm not found");
        return;
    }
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        try {
            const thesisId = document.getElementById("thesisId").value.trim();
            const grade = Number(document.getElementById("grade").value);
            const thesisTitle = document.getElementById("thesisTitle").value.trim();
            const defenseDate = document.getElementById("defenseDate").value;
            const payload = {
                thesisId,
                grade,
                metadata: {
                    thesisTitle,
                    defenseDate
                }
            };
            const result = await submit(payload);
            console.log(result);
            alert([
                "Submission successful",
                "",
                `Thesis ID: ${result.thesisId}`,
                `Hash: ${result.docHash}`,
                `Received At: ${result.receivedAt}`
            ].join("\n"));
            form.reset();
        }
        catch (err) {
            console.error(err);
            alert(err instanceof Error
                ? err.message
                : "Submission failed");
        }
    });
});
