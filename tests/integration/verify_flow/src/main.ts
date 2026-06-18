import { submit } from "./api/submissions";
import type { SubmissionRequest } from "./models/SubmissionRequest";
import type { SubmissionResponse } from "./models/SubmissionResponse";

document.addEventListener("DOMContentLoaded", () => {

    const form = document.getElementById(
        "studentForm"
    ) as HTMLFormElement | null;

    if (!form) {
        console.error("studentForm not found");
        return;
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        try {

            const thesisId =
                (document.getElementById(
                    "thesisId"
                ) as HTMLInputElement).value.trim();

            const grade =
                Number(
                    (document.getElementById(
                        "grade"
                    ) as HTMLInputElement).value
                );

            const thesisTitle =
                (document.getElementById(
                    "thesisTitle"
                ) as HTMLInputElement).value.trim();

            const defenseDate =
                (document.getElementById(
                    "defenseDate"
                ) as HTMLInputElement).value;

            const payload: SubmissionRequest = {
                thesisId,
                grade,

                metadata: {
                    thesisTitle,
                    defenseDate
                }
            };

            const result: SubmissionResponse =
                await submit(payload);

            console.log(result);

            alert(
                [
                    "Submission successful",
                    "",
                    `Thesis ID: ${result.thesisId}`,
                    `Hash: ${result.docHash}`,
                    `Received At: ${result.receivedAt}`
                ].join("\n")
            );

            form.reset();

        } catch (err) {

            console.error(err);

            alert(
                err instanceof Error
                    ? err.message
                    : "Submission failed"
            );
        }
    });

});