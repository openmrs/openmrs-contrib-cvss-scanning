
let detailsEls = document.getElementsByClassName("details-category");

let openButton = document.getElementById("open-categories");
let closeButton = document.getElementById("close-categories");
let sortCategoryDropdown = document.getElementById("category-sorting-options");
let ascnDescDropdown = document.getElementById("category-ascn-desc-options");

function setDetailsOpen(bool) {
    for (i = 0; i < detailsEls.length; i++) {
        detailsEls[i].open = bool;
    }
}

function sortDetailsPanel(sortBy, isDescending) {

    const testResultsWrappers = Array.from(document.getElementsByClassName("test-results"));

    const panels = [];

    for (let i = 0; i < testResultsWrappers.length; i++) {
        const currentTestResultWrapper = testResultsWrappers[i];
        const categoryTitleEl = currentTestResultWrapper.getElementsByClassName("category-title-text")[0];
        
        // category name
        let categoryTitleText = categoryTitleEl.textContent;

        // pass count
        let passCount = currentTestResultWrapper.getElementsByClassName("pass-count")[0];
        let passCountText = passCount.textContent;

        // fail count
        let failCount = currentTestResultWrapper.getElementsByClassName("fail-count")[0];
        let failCountText = failCount.textContent;

        // total tests
        let totalTests = currentTestResultWrapper.getElementsByClassName("total-tests")[0];
        let totalTestsText = totalTests.textContent;

        // max cvss
        let maxCVSS = currentTestResultWrapper.getElementsByClassName("max-cvss-score-text")[0];
        let maxCVSSText = "";

        // if all passing tests
        if (maxCVSS == undefined) {
            maxCVSSText = "0.0";
        } else {
            maxCVSSText = maxCVSS.textContent;
        }

        categoryTitleText = categoryTitleText.trim();
        passCountText = passCountText.trim();
        failCountText = failCountText.trim();
        totalTestsText = totalTestsText.trim();
        maxCVSSText = maxCVSSText.trim();
    
        //sortable
        panels.push({
            currentTestResultWrapper: currentTestResultWrapper,
            categoryTitleText: categoryTitleText,
            passCount: passCountText,
            failCount: failCountText,
            totalTests: totalTestsText,
            maxCVSS: maxCVSSText,
        });
    }

    // sort by
    const sortByMap = {
        "alpha": "categoryTitleText",
        "fail": "failCount",
        "pass": "passCount",
        "tests": "totalTests",
        "max-cvss": "maxCVSS",
    };

    const sortKey = sortByMap[sortBy];

    panels.sort(function (a,b) {
        const result = a[sortKey].localeCompare(b[sortKey], undefined, {
            numeric: true,
            sensitivity: 'base',
        });

        return isDescending ? -result : result;
    });
    
    if (panels.length === 0) return;

    const fragment = document.createDocumentFragment();

    for (let i = 0; i < panels.length; i++) {
        fragment.appendChild(panels[i].currentTestResultWrapper);
    }

    const parent = document.getElementById("categories");
    parent.appendChild(fragment);
}

openButton.addEventListener('click', () => {
    setDetailsOpen(true);
});

closeButton.addEventListener('click', () => {
    setDetailsOpen(false);
});

sortCategoryDropdown.addEventListener('change', (e) => {
    
    let value = e.target.value;
    let isDescending = ascnDescDropdown.value == "desc";

    sortDetailsPanel(value, isDescending);

});

ascnDescDropdown.addEventListener('change', (e) => {
    
    let value = sortCategoryDropdown.value;
    let isDescending = e.target.value == "desc";

    sortDetailsPanel(value, isDescending);
});