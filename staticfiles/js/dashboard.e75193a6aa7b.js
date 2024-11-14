function searchFunction() {
    let input = document.getElementById("searchUsers").value.toLowerCase();
    let rows = document.querySelectorAll("#usersTable tbody tr");

    rows.forEach(row => {
        let cells = Array.from(row.cells);
        let match = cells.some(cell => cell.textContent.toLowerCase().includes(input));
        row.style.display = match ? "" : "none";
    });
}
