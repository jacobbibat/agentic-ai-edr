from flask import Flask, jsonify

from database.connection import initialise_database
from database.repository import SecurityRepository

app = Flask(__name__)

# Initialise databasse
initialise_database()

# Create our repository
repository = SecurityRepository()

@app.get("/api/alerts")
def get_alerts():
    """Return all stored security alerts."""

    alerts = repository.get_all_alerts()

    return jsonify(alerts)

if __name__ == "__main__":
    app.run(debug=True)