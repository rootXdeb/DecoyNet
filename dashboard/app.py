"""
Flask dashboard application — simple polling based, no Socket.IO needed.
"""

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "hp-dashboard-secret-change-in-prod"

    from dashboard.routes import bp
    app.register_blueprint(bp)

    return app
