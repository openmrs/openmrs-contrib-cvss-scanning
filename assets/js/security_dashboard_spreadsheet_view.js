// JavaScript codes for the Security Dashboard Spreadsheet View

let spreadsheetTable = document.getElementById("spreadsheet-table");
let tableHead = document.getElementsByTagName("thead")[0];
let tableBody = document.getElementsByTagName("tbody")[0];
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

function searchByField(searchText, searchField) {

    // collect all rows and their cells in an object
    const rows = getTableRows(tableBody);

    if (searchText.trim() == "") {
        for (let i = 0; i < rows.length; i++) {
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

    // sort by relevance (if no other sorts selected)
    let relevanceRank = new Map();
    results.forEach((result, index) => {
        relevanceRank.set(result.item.currentRow, index);
    });

    if (sortByRelevanceCheckbox.checked) {
        sortTableRows(tableBody, "Relevance", true, relevanceRank);
    }
}

tableHead.addEventListener('click', (e) => {
    tableHeadEventListener(e, tableHead, sortByRelevanceCheckbox);
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
        resetChevrons(chevrons);

        searchText = spreadsheetSearchBar.value;
        searchField = searchFieldSelect.value;

        searchByField(searchText, searchField);
    }
});

//begin with no chevrons
resetChevrons(chevrons);