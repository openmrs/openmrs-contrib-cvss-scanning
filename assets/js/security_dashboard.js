
let detailsEls = document.getElementsByClassName("details-category");

let openButton = document.getElementById("open-categories");
let closeButton = document.getElementById("close-categories");
let sortCategoryDropdown = document.getElementById("category-sorting-options");
let sortDirectionButton = document.getElementById("category-sort-direction");
let categorySearch = document.getElementById("category-search");
let categoriesEmpty = document.getElementById("categories-empty");

function setDetailsOpen(bool) {
    for (i = 0; i < detailsEls.length; i++) {
        detailsEls[i].open = bool;
    }
}

function sortDetailsPanel(sortBy, isDescending) {

    const panels = Array.from(document.getElementsByClassName("categories__item"));

    if (panels.length === 0) return;

    // sort by
    const sortByMap = {
        "alpha": "name",
        "fail": "failed",
        "pass": "passed",
        "tests": "total",
        "max-cvss": "maxCvss",
    };

    const sortKey = sortByMap[sortBy];

    panels.sort(function (a,b) {
        const result = a.dataset[sortKey].localeCompare(b.dataset[sortKey], undefined, {
            numeric: true,
            sensitivity: 'base',
        });

        return isDescending ? -result : result;
    });

    const fragment = document.createDocumentFragment();

    for (let i = 0; i < panels.length; i++) {
        fragment.appendChild(panels[i]);
    }

    const parent = document.getElementById("categories");
    parent.appendChild(fragment);
}

function filterCategories(query) {

    const panels = document.getElementsByClassName("categories__item");
    const normalizedQuery = query.trim().toLowerCase();
    let visibleCount = 0;

    for (let i = 0; i < panels.length; i++) {
        // data-search holds the category name and all of its test names
        const isMatch = normalizedQuery === "" || panels[i].dataset.search.includes(normalizedQuery);
        panels[i].hidden = !isMatch;

        if (isMatch) {
            visibleCount++;
        }
    }

    categoriesEmpty.hidden = visibleCount > 0;
    categoriesEmpty.textContent = "No categories match “" + query.trim() + "”.";
}

function isSortDescending() {
    return sortDirectionButton.dataset.descending === "true";
}

openButton.addEventListener('click', () => {
    setDetailsOpen(true);
});

closeButton.addEventListener('click', () => {
    setDetailsOpen(false);
});

sortCategoryDropdown.addEventListener('change', (e) => {
    sortDetailsPanel(e.target.value, isSortDescending());
});

sortDirectionButton.addEventListener('click', () => {
    const isDescending = !isSortDescending();

    sortDirectionButton.dataset.descending = isDescending;
    sortDirectionButton.setAttribute("aria-label", "Sort direction: " + (isDescending ? "descending" : "ascending"));
    sortDirectionButton.getElementsByClassName("categories__direction-label")[0].textContent = isDescending ? "Desc" : "Asc";

    sortDetailsPanel(sortCategoryDropdown.value, isDescending);
});

categorySearch.addEventListener('input', (e) => {
    filterCategories(e.target.value);
});

/* Table sorting */
let sortableTables = document.getElementsByClassName("sub-details-head");

for (let i = 0; i < sortableTables.length; i++) {
    sortableTables[i].addEventListener('click', (e) => {tableHeadEventListener(e, sortableTables[i], null);});
}

let allChevrons = document.getElementsByClassName("spreadsheet-chevron");
resetChevrons(allChevrons);
