
let details = document.getElementsByClassName("details-category");

let openButton = document.getElementById("open-categories");
let closeButton = document.getElementById("close-categories");

function setDetailsOpen(bool) {
    for (i = 0; i < details.length; i++) {
        details[i].open = bool;
    }
}

openButton.addEventListener('click', () => {
    setDetailsOpen(true);
});

closeButton.addEventListener('click', () => {
    setDetailsOpen(false);
});

//TODO: OPEN ALL FAILED, OPEN ALL PASSED (subdetails)

