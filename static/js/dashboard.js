async function loadDashboard() {
    try {
        // Retrieve dashboard statistics
        const statsResponse = await fetch("/api/dashboard/stats");

        if (!statsResponse.ok) {
            throw new Error("Failed to load dashboard statistics");
        }

        const stats = await statsResponse.json();

        // Update the summary cards
        document.getElementById("total-events").textContent =
            stats.total_events;

        document.getElementById("total-alerts").textContent =
            stats.total_alerts;

        document.getElementById("high-severity").textContent =
            stats.high_severity;

        // Retrieve security alerts
        const alertsResponse = await fetch("/api/alerts");

        if (!alertsResponse.ok) {
            throw new Error("Failed to load security alerts");
        }

        const alerts = await alertsResponse.json();

        const tableBody = document.getElementById("alerts-table-body");

        // Clear existing table rows
        tableBody.replaceChildren();

        // Handle an empty database
        if (alerts.length === 0) {
            const row = tableBody.insertRow();
            const cell = row.insertCell();

            cell.colSpan = 4;
            cell.textContent = "No security alerts found.";
            return;
        }

        // Display the 10 most recent alerts
        alerts.slice(0, 10).forEach(alert => {
            const row = tableBody.insertRow();

            row.insertCell().textContent = alert.rule_id;
            row.insertCell().textContent = alert.rule_name;

            // Use the shared severity function from utils.js
            row.insertCell().appendChild(createSeverityTag(alert.severity));

            row.insertCell().textContent = alert.status;
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

// Load dashboard information when the page opens
document.addEventListener("DOMContentLoaded", loadDashboard);