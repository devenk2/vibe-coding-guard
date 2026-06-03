# Safe Python file for testing Vibe Coding Guard
# This file should produce NO security findings

import os
import json
import hashlib
import subprocess
import sqlite3
import logging

logger = logging.getLogger(__name__)


def get_config():
    """Load configuration from environment variables."""
    return {
        "api_key": os.environ.get("API_KEY"),
        "database_url": os.environ.get("DATABASE_URL"),
        "debug": os.environ.get("DEBUG", "false").lower() == "true",
    }


def hash_data(data):
    """Hash data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()


def run_command(args):
    """Run a command safely using subprocess with argument list."""
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout


def query_user(conn, user_id):
    """Query user with parameterized SQL."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def process_data(raw_data):
    """Process data using safe JSON deserialization."""
    data = json.loads(raw_data)
    return data


def handle_error():
    """Proper error handling."""
    try:
        result = some_operation()
        return result
    except ValueError as e:
        logger.error("Validation failed: %s", e)
        raise
    except ConnectionError as e:
        logger.error("Connection failed: %s", e)
        return None
