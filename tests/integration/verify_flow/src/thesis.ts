// theses.ts (entry point for a theses.html page, or integrate into your existing page)
import { getThesis, getAllTheses } from "./api/thesis";
import type { Thesis } from "./models/Thesis";

function renderThesis(t: Thesis): string {
    return `
        <tr>
            <td>${t.thesisId}</td>
            <td>${t.metadata?.thesisTitle ?? "-"}</td>
            <td>${t.metadata?.DefenseDate ?? "-"}</td>
            <td>${t.grade}</td>
            <td>${t.hash ? "✅ notarized" : "⏳ pending"}</td>
        </tr>
    `;
}

async function loadAllTheses() {
    const tbody = document.getElementById("thesesTableBody");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="5">Loading...</td></tr>`;
    try {
        const theses = await getAllTheses();
        tbody.innerHTML = theses.length
            ? theses.map(renderThesis).join("")
            : `<tr><td colspan="5">No theses found.</td></tr>`;
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5">Error: ${err instanceof Error ? err.message : "unknown"}</td></tr>`;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    loadAllTheses();

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
            resultDiv.innerHTML = `<p class="error">${err instanceof Error ? err.message : "Not found"}</p>`;
        }
    });

    document.getElementById("refreshBtn")?.addEventListener("click", loadAllTheses);
});