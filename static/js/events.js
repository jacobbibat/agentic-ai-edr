let storedEvents = []

// Retrieve events from Flask
async function loadEvents() {
    try {
        const response = await fetch ("/api/events");

        if(!response.ok) {
            throw new Error("Failed to retrieve events");
        }
        storedEvents = await response.json();

        displayEvents(storedEvents);

    }  catch (error) {
        console.error("Error loading events: ", error);

        const tableBody = document.getElementById(
            "events-table-body"
        );

        const row = tableBody.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 6;
        cell.textContext = "Unable to load endpoint activities";
    }
}

// Display the retieved events in the table
function displayEvents(events) {
    const tableBody = document.getElementById(
        "events-table-body"
    );

    tableBody.replaceChildren();

    if (events.length === 0) {
        const row = tableBody.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 6;
        cell.textContext = "No events found";
        return;
    }

    events.forEach(event => {
        const row = tableBody.insertRow();

        const data = event.events_data;

        // Extract file names from Windows Paths
        const processName = (path) => {
            if (!path) return "Unknown";
            return path.split("\\").pop();
        };

        row.insertCell().textContext = event.timestamp;
        row.insertCell().textContext = event.endpoint;
        row.insertCell().textContext = event.sysmon_event_id;

        row.insertCell().textContext = processName(data.Image);
        row.insertCell().textContext = processName(data.ParentImage);

        const actionCell = row.insertCell();

        const button = document.createElement("button");

        button.className = "button is-small is-info";
        button.textContent = "View Details";

        button.addEventListener("click", () => {
            showEventDetails(event);
        });

        actionCell.appendChild(button);
    });
}

// Open the modal showing the original event
function showEventDetails(event) {
    const modal = document.getElementById(
        "events-detail-modal"
    );

    const jsonDisplay = document.getElementById(
        "event-json"
    );

    jsonDisplay.textContent = JSON.stringify(
        event.events_data,
        null,
        4
    );

    modal.classList.add("is-active");
}

//Close the modal
function closeEventDetails() {
    document.getElementById(
        "event-details-modal"
    ).classList.remove(is-active);
}

// Initialise the page
document.addEventListener("DOMContentLoaded", () => {
    loadEvents();

    document.getElementById("close-modal")
    .addEventListener("click", closeEventDetails);

    document.querySelector(
        "#event-detail-modal .modal-background"
    ).addEventListener("click", closeEventDetails);

    document.addEventListener("keydown", (event) => {
        if(event.key === "Escape") {
            closeEventDetails();
        }
    });
});