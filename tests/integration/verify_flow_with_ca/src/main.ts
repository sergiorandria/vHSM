import { login, getSession, clearSession } from "./api/auth";
import type { StoredSession } from "./api/auth";
import { submit } from "./api/submissions";
import { getThesis, getAllTheses } from "./api/thesis";
import type { SubmissionRequest } from "./models/SubmissionRequest";
import type { SubmissionResponse } from "./models/SubmissionResponse";
import type { Thesis } from "./models/Thesis";

function renderThesis(t: Thesis): string {
    const notarized = !!t.hash;
    return `
        <tr>
            <td>${t.thesisId}</td>
            <td>${t.metadata?.thesisTitle ?? "-"}</td>
            <td>${t.metadata?.DefenseDate ?? "-"}</td>
            <td>${t.grade}</td>
            <td><span class="badge ${notarized ? "notarized" : "pending"}">${notarized ? "Notarized" : "Pending"}</span></td>
        </tr>
    `;
}

async function loadAllTheses() {
    const tbody = document.getElementById("thesesTableBody");
    if (!tbody) return;

    tbody.innerHTML = `<tr class="empty-row"><td colspan="5">Loading…</td></tr>`;
    try {
        const theses = await getAllTheses();
        tbody.innerHTML = theses.length
            ? theses.map(renderThesis).join("")
            : `<tr class="empty-row"><td colspan="5">No theses found.</td></tr>`;
    } catch (err) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="5">Error: ${err instanceof Error ? err.message : "unknown"}</td></tr>`;
        if (err instanceof Error && err.message.toLowerCase().includes("session expired")) {
            showLogin();
        }
    }
}

function showApp(session: StoredSession) {
    document.getElementById("loginCard")?.classList.add("hidden");
    document.getElementById("appContent")?.classList.remove("hidden");

    const userLabel = document.getElementById("currentUser");
    if (userLabel) {
        userLabel.textContent = `${session.username} · ${session.roles.join(", ") || "no roles"}`;
    }

    loadAllTheses();
}

function showLogin() {
    document.getElementById("appContent")?.classList.add("hidden");
    document.getElementById("loginCard")?.classList.remove("hidden");
}

document.addEventListener("DOMContentLoaded", () => {
    // --- Session bootstrap ---
    const existingSession = getSession();
    if (existingSession) {
        showApp(existingSession);
    } else {
        showLogin();
    }

    // --- Login form ---
    const loginForm = document.getElementById("loginForm") as HTMLFormElement | null;
    loginForm?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const loginBtn = document.getElementById("loginBtn") as HTMLButtonElement;
        const errorEl = document.getElementById("loginError");
        if (errorEl) errorEl.textContent = "";

        const username = (document.getElementById("username") as HTMLInputElement).value.trim();
        const password = (document.getElementById("password") as HTMLInputElement).value;

        loginBtn.disabled = true;
        try {
            const session = await login(username, password);
            loginForm.reset();
            showApp(session);
        } catch (err) {
            if (errorEl) errorEl.textContent = err instanceof Error ? err.message : "Login failed";
        } finally {
            loginBtn.disabled = false;
        }
    });

    document.getElementById("logoutBtn")?.addEventListener("click", () => {
        clearSession();
        showLogin();
    });

    // --- Submission form ---
    const form = document.getElementById("studentForm") as HTMLFormElement | null;
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const submitBtn = document.getElementById("submitBtn") as HTMLButtonElement;

            try {
                const rawThesisId = (document.getElementById("ThesisId") as HTMLInputElement).value.trim();
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

                const payload: SubmissionRequest = {
                    ThesisId: rawThesisId,
                    Grade: parseFloat((document.getElementById("Grade") as HTMLInputElement).value),
                    Document: fileInput.files[0],
                    Title: (document.getElementById("Title") as HTMLInputElement).value,
                    Date: (document.getElementById("Date") as HTMLInputElement).value
                };

                submitBtn.disabled = true;
                const result: SubmissionResponse = await submit(payload);
                console.log("Succès serveur :", result);
                alert("Submission successful !");
                form.reset();
                await loadAllTheses();

            } catch (err) {
                console.error("Erreur attrapée :", err);
                const message = err instanceof Error ? err.message : "Submission failed";
                alert(message);
                if (message.toLowerCase().includes("session expired")) {
                    showLogin();
                }
            } finally {
                submitBtn.disabled = false;
            }
        });
    }

    // --- Theses table + search ---
    const searchForm = document.getElementById("searchForm") as HTMLFormElement | null;
    searchForm?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const idInput = document.getElementById("searchThesisId") as HTMLInputElement;
        const resultDiv = document.getElementById("searchResult");
        if (!resultDiv) return;

        try {
            const thesis = await getThesis(idInput.value.trim());
            resultDiv.innerHTML = `<pre>${JSON.stringify(thesis, null, 2)}</pre>`;
        } catch (err) {
            resultDiv.innerHTML = `<p class="error-text">${err instanceof Error ? err.message : "Not found"}</p>`;
        }
    });

    document.getElementById("refreshBtn")?.addEventListener("click", loadAllTheses);
});
