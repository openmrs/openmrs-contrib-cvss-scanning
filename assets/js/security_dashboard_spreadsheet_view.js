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
let sortByRelevanceCheckbox = document.getElementById("relevance-checkbox");

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

function getTableRows() {
    const tableBody = spreadsheetTable.getElementsByTagName("tbody")[0];
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

    return rows;
}

function sortTableRows(sortByField, isAscending, relevanceRank) {

    const rows = getTableRows();

    // sort by relevance
    if (sortByField == "Relevance") {
        rows.sort(function (a,b) {
            const rankA = relevanceRank.has(a.currentRow) ? relevanceRank.get(a.currentRow) : Infinity;
            const rankB = relevanceRank.has(b.currentRow) ? relevanceRank.get(b.currentRow) : Infinity;

            // unmatched rows (Infinity) always sink to the bottom,
            // regardless of ascending/descending
            if (rankA === Infinity && rankB === Infinity) return 0;
            if (rankA === Infinity) return 1;
            if (rankB === Infinity) return -1;

            const result = rankA - rankB;
            return isAscending ? result : -result;
        });
    }
    else {
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
    }
    
    if (rows.length === 0) return;

    const fragment = document.createDocumentFragment();

    for (let i = 0; i < rows.length; i++) {
        fragment.appendChild(rows[i].currentRow);
    }

    const parent = spreadsheetTable.getElementsByTagName("tbody")[0];
    parent.appendChild(fragment);
}

function searchByField(searchText, searchField) {

    // collect all rows and their cells in an object
    const rows = getTableRows();

    if (searchText.trim() == "") {
        for (let i = 0; i < rows.length; i++) {

            if (rows[i].classList != undefined) {
                console.log(rows[i]);
            }
            rows[i].currentRow.classList.remove("search-visible");
            rows[i].currentRow.classList.remove("search-invisible");
        }

        return;
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

    console.log(results);
    // sort by relevance (if no other sorts selected)
    let relevanceRank = new Map();
    results.forEach((result, index) => {
        relevanceRank.set(result.item.currentRow, index);
    });

    if (sortByRelevanceCheckbox.checked) {
        sortTableRows("Relevance", true, relevanceRank);
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

    sortByRelevanceCheckbox.checked = false;

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

sortByRelevanceCheckbox.addEventListener('change', (e) => {
    if (e.target.checked) {
        resetChevrons();

        searchText = spreadsheetSearchBar.value;
        searchField = searchFieldSelect.value;

        searchByField(searchText, searchField);
    }
});

//begin with no chevrons
resetChevrons();