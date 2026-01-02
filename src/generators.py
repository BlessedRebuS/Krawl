#!/usr/bin/env python3

"""
Generators for creating random fake data (credentials, API keys, etc.)
"""

import random
import string
import json
from templates import html_templates
from wordlists import get_wordlists

def random_username() -> str:
    """Generate random username"""
    wl = get_wordlists()
    return random.choice(wl.username_prefixes) + random.choice(wl.username_suffixes)


def random_password() -> str:
    """Generate random password"""
    wl = get_wordlists()
    templates = [
        lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=12)),
        lambda: f"{random.choice(wl.password_prefixes)}{random.randint(100, 999)}!",
        lambda: f"{random.choice(wl.simple_passwords)}{random.randint(1000, 9999)}",
        lambda: ''.join(random.choices(string.ascii_lowercase, k=8)),
    ]
    return random.choice(templates)()


def random_email(username: str = None) -> str:
    """Generate random email"""
    wl = get_wordlists()
    if not username:
        username = random_username()
    return f"{username}@{random.choice(wl.email_domains)}"

def random_server_header() -> str:
    """Generate random server header from wordlists"""
    wl = get_wordlists()
    return random.choice(wl.server_headers)

def random_api_key() -> str:
    """Generate random API key"""
    wl = get_wordlists()
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return random.choice(wl.api_key_prefixes) + key


def random_database_name() -> str:
    """Generate random database name"""
    wl = get_wordlists()
    return random.choice(wl.database_names)


def credentials_txt() -> str:
    """Generate fake credentials.txt with random data"""
    content = "# Production Credentials\n\n"
    for i in range(random.randint(3, 7)):
        username = random_username()
        password = random_password()
        content += f"{username}:{password}\n"
    return content


def passwords_txt() -> str:
    """Generate fake passwords.txt with random data"""
    content = "# Password List\n"
    content += f"Admin Password: {random_password()}\n"
    content += f"Database Password: {random_password()}\n"
    content += f"API Key: {random_api_key()}\n\n"
    content += "User Passwords:\n"
    for i in range(random.randint(5, 10)):
        username = random_username()
        password = random_password()
        content += f"{username} = {password}\n"
    return content


def users_json() -> str:
    """Generate fake users.json with random data"""
    wl = get_wordlists()
    users = []
    for i in range(random.randint(3, 8)):
        username = random_username()
        users.append({
            "id": i + 1,
            "username": username,
            "email": random_email(username),
            "password": random_password(),
            "role": random.choice(wl.user_roles),
            "api_token": random_api_key()
        })
    return json.dumps({"users": users}, indent=2)


def api_keys_json() -> str:
    """Generate fake api_keys.json with random data"""
    keys = {
        "stripe": {
            "public_key": "pk_live_" + ''.join(random.choices(string.ascii_letters + string.digits, k=24)),
            "secret_key": random_api_key()
        },
        "aws": {
            "access_key_id": "AKIA" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16)),
            "secret_access_key": ''.join(random.choices(string.ascii_letters + string.digits + '+/', k=40))
        },
        "sendgrid": {
            "api_key": "SG." + ''.join(random.choices(string.ascii_letters + string.digits, k=48))
        },
        "twilio": {
            "account_sid": "AC" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=32)),
            "auth_token": ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
        }
    }
    return json.dumps(keys, indent=2)


def api_response(path: str) -> str:
    """Generate fake API JSON responses with random data"""
    wl = get_wordlists()
    
    def random_users(count: int = 3):
        users = []
        for i in range(count):
            username = random_username()
            users.append({
                "id": i + 1,
                "username": username,
                "email": random_email(username),
                "role": random.choice(wl.user_roles)
            })
        return users
    
    responses = {
        '/api/users': json.dumps({
            "users": random_users(random.randint(2, 5)),
            "total": random.randint(50, 500)
        }, indent=2),
        '/api/v1/users': json.dumps({
            "status": "success",
            "data": [{
                "id": random.randint(1, 100),
                "name": random_username(),
                "api_key": random_api_key()
            }]
        }, indent=2),
        '/api/v2/secrets': json.dumps({
            "database": {
                "host": random.choice(wl.database_hosts),
                "username": random_username(),
                "password": random_password(),
                "database": random_database_name()
            },
            "api_keys": {
                "stripe": random_api_key(),
                "aws": 'AKIA' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
            }
        }, indent=2),
        '/api/config': json.dumps({
            "app_name": random.choice(wl.application_names),
            "debug": random.choice([True, False]),
            "secret_key": random_api_key(),
            "database_url": f"postgresql://{random_username()}:{random_password()}@localhost/{random_database_name()}"
        }, indent=2),
        '/.env': f"""APP_NAME={random.choice(wl.application_names)}
DEBUG={random.choice(['true', 'false'])}
APP_KEY=base64:{''.join(random.choices(string.ascii_letters + string.digits, k=32))}=
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE={random_database_name()}
DB_USERNAME={random_username()}
DB_PASSWORD={random_password()}
AWS_ACCESS_KEY_ID=AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}
AWS_SECRET_ACCESS_KEY={''.join(random.choices(string.ascii_letters + string.digits + '+/', k=40))}
STRIPE_SECRET={random_api_key()}
"""
    }
    return responses.get(path, json.dumps({"error": "Not found"}, indent=2))


def directory_listing(path: str) -> str:
    """Generate fake directory listing using wordlists"""
    wl = get_wordlists()
    
    files = wl.directory_files
    dirs = wl.directory_dirs
    
    selected_files = [(f, random.randint(1024, 1024*1024)) 
                      for f in random.sample(files, min(6, len(files)))]
    
    return html_templates.directory_listing(path, dirs, selected_files)
