function resetChevrons(chevrons) {
    // reset all chevrons
    for (let i = 0; i < chevrons.length; i++) {
        chevrons[i].style.display = "none";
        chevrons[i].classList.remove("flipped");
    }
}

function updateChevron(target, currentChevrons) {

    // if there is a chevron, flip it
    let currentChevron = target.getElementsByClassName("spreadsheet-chevron")[0];

    if (currentChevron.style.display != "none") {
        // flip it
        currentChevron.classList.toggle("flipped");
    }
    else {
        // if no chevron on the end
        // remove all chevrons
        resetChevrons(currentChevrons);

        // add new one
        currentChevron.style.display = "";
    }

}

function getTableRows(tableBody) {
    const tableRows = Array.from(tableBody.getElementsByTagName("tr"));

    const rows = [];

    for (let i = 0; i < tableRows.length; i++) {

        const currentRow = tableRows[i];

        // category name
        let categoryEl = currentRow.getElementsByClassName("row-category")[0];
        let categoryText = "";

        if (categoryEl != null) {
            categoryText = categoryEl.textContent;
        }

        // test name
        let testNameEl = currentRow.getElementsByClassName("row-test-name")[0];
        let testNameText = testNameEl.textContent;

        // parameters
        let parametersEl = currentRow.getElementsByClassName("row-params")[0];
        let parametersText = parametersEl.textContent;

        // description
        let descriptionEl = currentRow.getElementsByClassName("row-description")[0];
        let descriptionText = "";

        if (descriptionEl != null) {
            descriptionText = descriptionEl.textContent;
        }

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
        descriptionText = descriptionText.trim();
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
            descriptionText: descriptionText,
            severityText: severityText,
            statusText: statusText,
            cvssText: cvssText,
            durationText: durationText,
        });
    }

    return rows;
}

function sortTableRows(tableBody, sortByField, isAscending, relevanceRank) {

    const rows = getTableRows(tableBody);

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
            "Description": "description",
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

    const parent = tableBody;
    parent.appendChild(fragment);
}

function tableHeadEventListener(e, thead, sortByRelevanceCheckbox) {

    let target = e.target.closest('th');

    let currentTable = target.closest('table');
    let currentTableBody = currentTable.getElementsByTagName('tbody')[0];

    let sortByField = target.getElementsByTagName("span")[0].textContent;

    if (sortByField == 'Severity') {
        return;
    }

    // add a chevron
    let currentChevrons = thead.getElementsByClassName("spreadsheet-chevron");
    updateChevron(target, currentChevrons);

    if (sortByRelevanceCheckbox != null) {
        sortByRelevanceCheckbox.checked = false;
    }

    // sort by corresponding feature
    let isAscending = target.getElementsByClassName("spreadsheet-chevron")[0].classList.contains("flipped");
    sortTableRows(currentTableBody, sortByField, isAscending);
}