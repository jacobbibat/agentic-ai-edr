async function loadDashboard() {
    try {
        // Step 1: Retrieve dashboard statistics.
        const statsResponse = await fetch("/api/dashboard/stats");
        console.log("Loading dashboard statistics...");

        if (!statsResponse.ok) {
            throw new Error("Failed to load dashboard statistics");
        }

        const stats = await statsResponse.json();
        console.log("Statistics received:", stats);

        // Step 2: Update the summary cards.
        document.getElementById("total-events").textContent =
            stats.total_events;

        document.getElementById("total-alerts").textContent =
            stats.total_alerts;

        document.getElementById("high-severity").textContent =
            stats.high_severity;

        // Step 3: Retrieve security alerts.
        const alertsResponse = await fetch("/api/alerts");

        if (!alertsResponse.ok) {
            throw new Error("Failed to load security alerts");
        }

        const alerts = await alertsResponse.json();

        const tableBody = document.getElementById("alerts-table-body");

        // Clear the loading message.
        tableBody.replaceChildren();

        // Step 4: Handle an empty database.
        if (alerts.length === 0) {
            const row = tableBody.insertRow();
            const cell = row.insertCell();

            cell.colSpan = 4;
            cell.textContent = "No security alerts found.";
            return;
        }

        // Step 5: Display the 10 most recent alerts.
        alerts.slice(0, 10).forEach(alert => {
            const row = tableBody.insertRow();

            const ruleIdCell = row.insertCell();
            ruleIdCell.textContent = alert.rule_id;

            const ruleNameCell = row.insertCell();
            ruleNameCell.textContent = alert.rule_name;

            const severityCell = row.insertCell();
            const severityTag = document.createElement("span");

            severityTag.classList.add("tag");

            if (alert.severity === "High") {
                severityTag.classList.add("is-danger");
            } else if (alert.severity === "Medium") {
                severityTag.classList.add("is-warning");
            } else {
                severityTag.classList.add("is-info");
            }

            severityTag.textContent = alert.severity;
            severityCell.appendChild(severityTag);

            const statusCell = row.insertCell();
            statusCell.textContent = alert.status;
        });

    } catch (error) {
        console.error("Dashboard loading failed:", error);

        const tableBody = document.getElementById("alerts-table-body");
        tableBody.replaceChildren();

        const row = tableBody.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 4;
        cell.textContent = "Unable to load security data.";
    }
}

// Load dashboard information when the page opens.
document.addEventListener("DOMContentLoaded", loadDashboard);
