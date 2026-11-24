from flask import Flask, jsonify, render_template

from database.connection import (
    DATABASE_PATH,
    initialise_database,
)
from database.repository import SecurityRepository


def create_app(database_path=DATABASE_PATH):
    """Create and configure the Flask application."""

    app = Flask(__name__)

    # Initialise the specified database.
    initialise_database(database_path)

    # Create repository for this application.
    repository = SecurityRepository(database_path)

    @app.get("/api/alerts")
    def get_alerts():
        """Return all security alerts as JSON."""

        alerts = repository.get_all_alerts()

        return jsonify(alerts)

    # New dashboard route.
    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    # Dashboard Stats API
    @app.get("/api/dashboard/stats")
    def dashboard_stats():
        """Return event and alert statistics."""

        stats = repository.get_dashboard_stats()

        return jsonify(stats)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", debug=True)
