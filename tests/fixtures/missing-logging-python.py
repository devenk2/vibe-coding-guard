# Python file with logging configured but sensitive ops without log calls
# This should trigger the missing-logging check

import logging
from database import db

logger = logging.getLogger(__name__)


def authenticate(username, password):
    user = db.query("SELECT * FROM users WHERE username = ?", (username,))
    if user and user.check_password(password):
        return user
    return None


def delete_user(user_id):
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()


def reset_password(user_id, new_password):
    hashed = hash_password(new_password)
    db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
    db.commit()
