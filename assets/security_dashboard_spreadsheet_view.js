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

// searching
let spreadsheetSearchBar = document.getElementById("spreadsheet-search-bar");
let searchFieldSelect = document.getElementById("searchField");

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

function searchByField(searchText, searchField) {

    // collect all rows and their cells in an object
    const tableBody = spreadsheetTable.getElementsByTagName("tbody")[0]
    const tableRows = Array.from(tableBody.getElementsByTagName("tr"));

    if (searchText.trim() == "") {
        for (let i = 0; i < tableRows.length; i++) {
            tableRows[i].style.display = "";
        }

        return;
    }

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

        // severity
        let severityEl = currentRow.getElementsByClassName("row-severity")[0];
        let severityText = severityEl.textContent;

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
        severityText = severityText.trim();
        statusText = statusText.trim();
        cvssText = cvssText.trim();
        durationText = durationText.trim();
    
        //sortable
        rows.push({
            uniqueId: i,
            currentRow: currentRow,
            categoryText: categoryText,
            testNameText: testNameText,
            parametersText: parametersText,
            severityText: severityText,
            statusText: statusText,
            cvssText: cvssText,
            durationText: durationText,
        });
    }

    // sort by
    const searchFieldMap = {
        "Category": "categoryText",
        "Test Name": "testNameText",
        "Parameters": "parametersText",
        "Severity": "severityText",
        "Status": "statusText",
        "CVSS Score": "cvssText",
        "Duration": "durationText",
    };

    let keys = [];

    if (searchField == "") {
        keys = [
            'categoryText',
            'testNameText',
            'parametersText',
            'severityText',
            'statusText',
            'cvssText',
            'durationText',
        ];
    } else {
        keys = [
            searchFieldMap[searchField]
        ];
    }

    // use object and search field to search
    const fuse = new Fuse(rows, {
        keys: keys,
        includeScore: true,
        threshold: 0.5,
    });

    // use results to set display
    const results = fuse.search(searchText);
    
    for (let i = 0; i < rows.length; i++) {
        // if row is in the results, display
        let hasResult = results.some(result => result.item.uniqueId === rows[i].uniqueId);

        if (hasResult) {
            rows[i].currentRow.classList.add("search-visible");
            rows[i].currentRow.classList.remove("search-invisible");
        } else {
            rows[i].currentRow.classList.remove("search-visible");
            rows[i].currentRow.classList.add("search-invisible");
        }
    }
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

function setPassFailRowsDisplay(e, rows) {
    for (let i = 0; i < rows.length; i++) {

        if (e.target.checked) {
            rows[i].classList.remove("pass-fail-invisible");
        }
        else {
            rows[i].classList.add("pass-fail-invisible");
        }
    }
}

passCheckbox.addEventListener('change', (e) => {
    setPassFailRowsDisplay(e, passedRows);
});

failCheckbox.addEventListener('change', (e) => {
    setPassFailRowsDisplay(e, failedRows);
});

// search bar
spreadsheetSearchBar.addEventListener('input', (e) => {
    searchText = e.target.value;
    searchField = searchFieldSelect.value;

    searchByField(searchText, searchField);
});

searchFieldSelect.addEventListener('change', (e) => {
    searchText = spreadsheetSearchBar.value;
    searchField = e.target.value;

    searchByField(searchText, searchField);
});

//begin with no chevrons
resetChevrons();