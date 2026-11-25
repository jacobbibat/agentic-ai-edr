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

        cell.colSpan = 7;
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

        cell.colSpan = 7;
        cell.textContent = "No Security alerts found";
        return;
    }

    // Create a table row for every alert
    alerts.forEach(alert => {
        const row = tableBody.insertRow();

        //Populate table cells
        row.insertCell().textContent = alert.id;
        row.insertCell().textContent = alert.timestamp;
        row.insertCell().textContent = alert.endpoint;
        row.insertCell().textContent = alert.rule_name;
        row.insertCell().appendChild(createSeverityTag(alert.severity));
        row.insertCell().textContent = alert.status;

        // Action cell from within the table
        const actionCell = row.insertCell();
        const button = document.createElement("button");

        button.className = "button is-small is-info";
        button.textContent = "View Details";

        // Action for when clicked
        button.addEventListener("click", () => {
            showAlertDetails(alert);
        });

        actionCell.appendChild(button);
    });
}

// Modal for showing alert details
function showAlertDetails(alert) {
    const modal = document.getElementById(
        "alert-detail-modal"
    );

    const evidenceDisplay = document.getElementById(
        "alert-evidence"
    );

    // Convert evidence object into readable JSON
    evidenceDisplay.textContent = JSON.stringify(
        alert.evidence,
        null,
        4
    );

    // Modal visable
    modal.classList.add("is-active");
}

// Close the alert details modal
function closeAlertDetails() {
    document.getElementById(
        "alert-detail-modal"
    ).classList.remove("is-active");
}

// Initialisation of the page when HTML is loaded
document.addEventListener("DOMContentLoaded", () => {
    // Retrieve and display alerts
    loadAlerts();

    // Closable Modal
    document.getElementById("close-modal").addEventListener("click", closeAlertDetails);

    // Closable if you click outside of modal
    document.querySelector("#alert-detail=modal .modal-background").addEventListener("click", closeAlertDetails);

    //Closable pressing escape
    document.addEventListener("keydown", (event) => {
        if(event/key ==="Escape") {
            closeAlertDetails();
        }
    });
});

