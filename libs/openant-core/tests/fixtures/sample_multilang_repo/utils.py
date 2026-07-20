"""Sample utility module for testing."""


def sanitize_input(value):
    if not isinstance(value, str):
        return str(value)
    return value.strip()


def validate_email(email):
    return "@" in email and "." in email
