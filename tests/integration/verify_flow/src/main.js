import { sendJSON } from "./api/studentApi";
const form = document.querySelector("#studentForm");
form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const studentThesisInfo = {
        name: document.getElementById("name").value,
        thesisTitle: document.getElementById("email").value,
        grade: Number(document.getElementById("grade").value)
    };
    await sendJSON(studentThesisInfo);
});
