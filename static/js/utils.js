function createSeverityTag(severity) {

    // Create a span element
    const tag = document.createElement("span");

    // Assign the severity text and Bulma class
    tag.textContent = severity;
    tag.className = "tag";

    // Assign a colour based on severity
    if (severity === "High") {
        tag.classList.add("is-danger");
    } else if (severity === "Medium") {
        tag.classList.add("is-warning");
    } else if (severity === "Low") {
        tag.classList.add("is-success");
    } else {
        tag.classList.add("is-info");
    }

    // Return the created HTML element
    return tag;
}

function highlightNav() {
    const currentPage = window.location.pathname;

    document.querySelectorAll(".menu-list a").forEach(link => {
        if (link.pathname === currentPage) {
            link.classList.add("is-active");
        }
    });
}
highlightNav();