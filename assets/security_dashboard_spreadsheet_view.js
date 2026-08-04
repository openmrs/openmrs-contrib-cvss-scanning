// JavaScript codes for the Security Dashboard Spreadsheet View

let spreadsheetTable = document.getElementById("spreadsheet-table");
let tableHead = document.getElementsByTagName("thead")[0];
let tableHeaders = tableHead.getElementsByTagName("th");
let chevrons = document.getElementsByClassName("spreadsheet-chevron");

function resetChevrons() {
    // reset all chevrons
    for (let i = 0; i < chevrons.length; i++) {
        chevrons[i].style.display = "none";
        chevrons[i].classList.remove("flipped");
    }
}

function updateChevron(target) {

    // if there is a chevron, flip it
    let currentChevron = target.getElementsByClassName("spreadsheet-chevron")[0];

    if (currentChevron.style.display != "none") {
        // flip it
        currentChevron.classList.toggle("flipped");
    }
    else {
        // if no chevron on the end
        // remove all chevrons
        resetChevrons();

        // add new one
        currentChevron.style.display = "";
    }

}

function sortTableRows() {

}

tableHead.addEventListener('click', (e) => {

    let target = e.target.closest('th');

    // add a chevron
    updateChevron(target);
    // sort by corresponding feature
    sortTableRows();
});

//begin with no chevrons
resetChevrons();