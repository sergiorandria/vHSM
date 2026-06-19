import { submit } from "./api/submissions";
import type { SubmissionRequest } from "./models/SubmissionRequest";
import type { SubmissionResponse } from "./models/SubmissionResponse";

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("studentForm") as HTMLFormElement | null;

    if (!form) {
        console.error("studentForm not found");
        return;
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        try {
            // Extraction AU MOMENT du clic sur Submit
            const rawThesisId = (document.getElementById("ThesisId") as HTMLInputElement).value.trim();
            
            console.log("Valeur brute saisie dans le formulaire :", rawThesisId);

            // Validation locale stricte avant l'envoi
            const thesisIdPattern = /^[a-zA-Z0-9_-]{1,128}$/;
            if (!thesisIdPattern.test(rawThesisId)) {
                alert("Erreur locale : L'ID de la thèse est invalide. Lettres, chiffres, '-' et '_' uniquement.");
                return;
            }

            const fileInput = document.getElementById("Document") as HTMLInputElement;
            if (!fileInput.files || fileInput.files.length === 0) {
                alert("Erreur : Veuillez sélectionner un document.");
                return;
            }
            const fileToUpload = fileInput.files[0];

            const payload: SubmissionRequest = {
                ThesisId: rawThesisId,
                Grade: parseFloat((document.getElementById("Grade") as HTMLInputElement).value),
                Document: fileToUpload,
                Metadata: {
                    title: (document.getElementById("Title") as HTMLInputElement).value,
                    date: (document.getElementById("Date") as HTMLInputElement).value
                }
            };

            const result: SubmissionResponse = await submit(payload);
            console.log("Succès serveur :", result);

            alert("Submission successful !");
            form.reset();

        } catch (err) {
            console.error("Erreur attrapée :", err);
            alert(err instanceof Error ? err.message : "Submission failed");
        }
    });
});
