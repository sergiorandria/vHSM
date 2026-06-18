import { sendJSON } from "./api/studentApi";
import { Student } from "./models/Student";

const form = document.querySelector(
    "#studentForm"
) as HTMLFormElement;

form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const studentThesisInfo: Student = {
        name: (document.getElementById("name") as HTMLInputElement).value,
        thesisTitle: (document.getElementById("email") as HTMLInputElement).value,
        grade: Number(
            (document.getElementById("grade") as HTMLInputElement).value
        )
    };

    await sendJSON(studentThesisInfo);
});