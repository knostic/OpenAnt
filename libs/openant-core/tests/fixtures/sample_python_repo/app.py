"""Sample Flask app for testing."""
from flask import Flask, request, jsonify
from .db import get_user, create_user

app = Flask(__name__)


@app.route("/users/<int:user_id>")
def get_user_endpoint(user_id):
    user = get_user(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(user)


@app.route("/users", methods=["POST"])
def create_user_endpoint():
    data = request.get_json()
    name = data.get("name")
    if not name:
        return jsonify({"error": "Name required"}), 400
    user = create_user(name)
    return jsonify(user), 201
