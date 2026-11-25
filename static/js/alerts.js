let storedAlerts = [];

//Retrieve alerts from Flask
async function loadAlerts() {
    try {
        const response = await fetch("/api/alerts");

        if(!response.ok) {
            throw new Error("Failed to retrieve alerts");
        }

        // Convert JSON response into JS array
        storedAlerts = await response.json();

        console.log(storedAlerts);

        // Display the alerts
        displayAlerts(storedAlerts);

    } catch(error) {
        console.error("Error loading alerts:", error);

        const tableBody = document.getElementById(
            "alerts-table-body"
        );

        tableBody.replaceChildren();

        const row = tableBody.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 6;
        cell.textContent ="Unable to load security alerts";
    }
}

// Display the retrieved alerts in the table
function displayAlerts(alerts) {
    const tableBody = document.getElementById(
        "alerts-table-body"
    );

    //remove existing table rows
    tableBody.replaceChildren();

    //Check whether alerts exist
    if(alerts.length == 0) {
        const row = tableBody.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 6;
        cell.textContent = "No Security alerts found";
        return;
    }

    // Create a table row for every alert
    alerts.forEach(alert => {
        const row = tableBody.insertRow();
        const alertID = `ALT-${String(alert.id).padStart(3,"0")}`; // So it can be represented as ALT-001 ->

        //Populate table cells
        row.insertCell().textContent = alertID;
        row.insertCell().textContent = alert.rule_name;
        row.insertCell().appendChild(createSeverityTag(alert.severity));
        row.insertCell().textContent = alert.status;
        row.insertCell().textContent = alert.classification ?? "-";
        row.insertCell().textContent = alert.timestamp;

        // Row to be clickable
        row.classList.add("alert-row");
        row.tabIndex = 0;
        row.setAttribute("role","button");

        row.addEventListener("click", () => {
            showAlertDetails(alert);
        });
    });
}

// Modal for showing alert details
function showAlertDetails(alert) {
    const modal = document.getElementById(
        "alert-detail-modal"
    );
    // Display alert ID in the modal header
    const alertID = `ALT-${String(alert.id).padStart(3, "0")}`;

    document.getElementById("detail-alert-id").textContent = alertID;

    // Display severity
    const severityDisplay = document.getElementById(
        "detail-severity"
    );

    severityDisplay.replaceChildren();
    severityDisplay.appendChild(
        createSeverityTag(alert.severity)
    );

    switchTab("overview");
    // Open the modal
    modal.classList.add("is-active");
}

// Close the alert details modal
function closeAlertDetails() {
    document.getElementById(
        "alert-detail-modal"
    ).classList.remove("is-active");
}

function switchTab(tabName) {

    // Remove highlight from existing tabs
    document.querySelectorAll("#alert-detail-modal [data-tab]")
        .forEach(tab => {
            tab.classList.remove("is-active");
        });

    // Hide all tab content
    document.querySelectorAll("#alert-detail-modal [id^='tab-']")
        .forEach(content => {
            content.classList.add("is-hidden");
        });

    // Highlight the selected tab
    document.querySelector(
        `#alert-detail-modal [data-tab="${tabName}"]`
    ).classList.add("is-active");

    // Display selected tab content
    document.getElementById(`tab-${tabName}`)
        .classList.remove("is-hidden");
}

// Initialisation of the page when HTML is loaded
document.addEventListener("DOMContentLoaded", () => {
    // Retrieve and display alerts
    loadAlerts();

    // Closable Modal
    document.getElementById("close-modal").addEventListener("click", closeAlertDetails);

    // Closable if you click outside of modal
    document.addEventListener("click", (event) => {
        const modal = document.getElementById("alert-detail-modal");

        if (
            modal.classList.contains("is-active") &&
            !modal.contains(event.target) &&
            !event.target.closest(".alert-row")
        ) {
            closeAlertDetails();
        }
    });

    //Modal tab navigation
    document.querySelectorAll("#alert-detail-modal [data-tab]")
        .forEach(tab => {
            tab.querySelector("a").addEventListener("click", (event) => {
                event.preventDefault();
                switchTab(tab.dataset.tab);
            });
        });

    // Close modal using footer button
    document.getElementById("close-modal-footer")
        .addEventListener("click", closeAlertDetails);

    //Closable pressing escape
    document.addEventListener("keydown", (event) => {
        if(event.key ==="Escape") {
            closeAlertDetails();
        }
    });
});


