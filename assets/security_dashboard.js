
let details = document.getElementsByClassName("details-category");

//TODO: Set to a button on the screen (on top bar or something)
document.addEventListener('keydown', (e) => {
    if (e.key == 'k') {
        for (i = 0; i < details.length; i++) {
            details[i].open = false;
        }
    } else if (e.key == 'j') {
        for (i = 0; i < details.length; i++) {
            details[i].open = true;
        }
    }
});

//TODO: OPEN ALL FAILED, OPEN ALL PASSED (subdetails)

