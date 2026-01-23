#!/usr/bin/env python3

import random
import re
from typing import Optional, Tuple
from wordlists import get_wordlists


def detect_sql_injection_pattern(query_string: str) -> Optional[str]:
    if not query_string:
        return None

    query_lower = query_string.lower()

    patterns = {
        "quote": [r"'", r'"', r"`"],
        "comment": [r"--", r"#", r"/\*", r"\*/"],
        "union": [r"\bunion\b", r"\bunion\s+select\b"],
        "boolean": [r"\bor\b.*=.*", r"\band\b.*=.*", r"'.*or.*'.*=.*'"],
        "time_based": [r"\bsleep\b", r"\bwaitfor\b", r"\bdelay\b", r"\bbenchmark\b"],
        "stacked": [r";.*select", r";.*drop", r";.*insert", r";.*update", r";.*delete"],
        "command": [r"\bexec\b", r"\bexecute\b", r"\bxp_cmdshell\b"],
        "info_schema": [r"information_schema", r"table_schema", r"table_name"],
    }

    for injection_type, pattern_list in patterns.items():
        for pattern in pattern_list:
            if re.search(pattern, query_lower):
                return injection_type

    return None


def get_random_sql_error(
    db_type: str = None, injection_type: str = None
) -> Tuple[str, str]:
    wl = get_wordlists()
    sql_errors = wl.sql_errors

    if not sql_errors:
        return ("Database error occurred", "text/plain")

    if not db_type:
        db_type = random.choice(list(sql_errors.keys()))

    db_errors = sql_errors.get(db_type, {})

    if injection_type and injection_type in db_errors:
        errors = db_errors[injection_type]
    elif "generic" in db_errors:
        errors = db_errors["generic"]
    else:
        all_errors = []
        for error_list in db_errors.values():
            if isinstance(error_list, list):
                all_errors.extend(error_list)
        errors = all_errors if all_errors else ["Database error occurred"]

    error_message = random.choice(errors) if errors else "Database error occurred"

    if "{table}" in error_message:
        tables = ["users", "products", "orders", "customers", "accounts", "sessions"]
        error_message = error_message.replace("{table}", random.choice(tables))

    if "{column}" in error_message:
        columns = ["id", "name", "email", "password", "username", "created_at"]
        error_message = error_message.replace("{column}", random.choice(columns))

    return (error_message, "text/plain")


def generate_sql_error_response(
    query_string: str, db_type: str = None
) -> Tuple[str, str, int]:
    injection_type = detect_sql_injection_pattern(query_string)

    if not injection_type:
        return (None, None, None)

    error_message, content_type = get_random_sql_error(db_type, injection_type)

    status_code = 500

    if random.random() < 0.3:
        status_code = 200

    return (error_message, content_type, status_code)


def get_sql_response_with_data(path: str, params: str) -> str:
    import json
    from generators import random_username, random_email, random_password

    injection_type = detect_sql_injection_pattern(params)

    if injection_type in ["union", "boolean", "stacked"]:
        data = {
            "success": True,
            "results": [
                {
                    "id": i,
                    "username": random_username(),
                    "email": random_email(),
                    "password_hash": random_password(),
                    "role": random.choice(["admin", "user", "moderator"]),
                }
                for i in range(1, random.randint(2, 5))
            ],
        }
        return json.dumps(data, indent=2)

    return json.dumps(
        {"success": True, "message": "Query executed successfully", "results": []},
        indent=2,
    )
