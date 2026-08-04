// JavaScript codes for the Security Dashboard Spreadsheet View

let spreadsheetTable = document.getElementById("spreadsheet-table");
let tableHead = document.getElementsByTagName("thead")[0];
let tableHeaders = tableHead.getElementsByTagName("th");
let chevrons = document.getElementsByClassName("spreadsheet-chevron");

// pass / fail filtering
let passedRows = document.getElementsByClassName("pass-row");
let failedRows = document.getElementsByClassName("fail-row");
let passCheckbox = document.getElementById("pass-checkbox");
let failCheckbox = document.getElementById("fail-checkbox");

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

function sortTableRows(sortByField, isAscending) {

    const tableBody = spreadsheetTable.getElementsByTagName("tbody")[0]
    const tableRows = Array.from(tableBody.getElementsByTagName("tr"));

    const rows = [];

    for (let i = 0; i < tableRows.length; i++) {

        const currentRow = tableRows[i];
        const categoryEl = currentRow.getElementsByClassName("row-category")[0];

        // category name
        let categoryText = categoryEl.textContent;

        // test name
        let testNameEl = currentRow.getElementsByClassName("row-test-name")[0];
        let testNameText = testNameEl.textContent;

        // parameters
        let parametersEl = currentRow.getElementsByClassName("row-params")[0];
        let parametersText = parametersEl.textContent;

        // status
        let statusEl = currentRow.getElementsByClassName("row-status")[0];
        let statusText = statusEl.textContent;

        // CVSS
        let cvssEl = currentRow.getElementsByClassName("row-cvss")[0];
        let cvssText = cvssEl.textContent;

        // duration
        let durationEl = currentRow.getElementsByClassName("row-duration")[0];
        let durationText = durationEl.textContent;

        categoryText = categoryText.trim();
        testNameText = testNameText.trim();
        parametersText = parametersText.trim();
        statusText = statusText.trim();
        cvssText = cvssText.trim();
        durationText = durationText.trim();
    
        //sortable
        rows.push({
            currentRow: currentRow,
            categoryText: categoryText,
            testNameText: testNameText,
            parametersText: parametersText,
            statusText: statusText,
            cvssText: cvssText,
            durationText: durationText,
        });
    }

    // sort by
    const sortByMap = {
        "Category": "categoryText",
        "Test Name": "testNameText",
        "Parameters": "parametersText",
        "Status": "statusText",
        "CVSS Score (Baseline)": "cvssText",
        "Duration": "durationText",
    };

    const sortKey = sortByMap[sortByField];

    rows.sort(function (a,b) {
        const result = a[sortKey].localeCompare(b[sortKey], undefined, {
            numeric: true,
            sensitivity: 'base',
        });

        return isAscending ? result : -result;
    });
    
    if (rows.length === 0) return;

    const fragment = document.createDocumentFragment();

    for (let i = 0; i < rows.length; i++) {
        fragment.appendChild(rows[i].currentRow);
    }

    const parent = tableBody;
    parent.appendChild(fragment);
}

tableHead.addEventListener('click', (e) => {

    let target = e.target.closest('th');
    let sortByField = target.getElementsByTagName("span")[0].textContent;

    if (sortByField == 'Severity') {
        return;
    }

    // add a chevron
    updateChevron(target);
    // sort by corresponding feature
    let isAscending = target.getElementsByClassName("spreadsheet-chevron")[0].classList.contains("flipped");
    sortTableRows(sortByField, isAscending);
});

passCheckbox.addEventListener('change', (e) => {

    let displayValue = e.target.checked == true ? "" : "none";

    for (let i = 0; i < passedRows.length; i++) {
        passedRows[i].style.display = displayValue;
    }
});

failCheckbox.addEventListener('change', (e) => {

    let displayValue = e.target.checked == true ? "" : "none";

    for (let i = 0; i < failedRows.length; i++) {
        failedRows[i].style.display = displayValue;
    }
});

//begin with no chevrons
resetChevrons();