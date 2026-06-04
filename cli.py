import os
import sys
import json
import click
import requests

# ---------------------------------------------------------------------------
# Configuration – adjust as needed
# ---------------------------------------------------------------------------
API_URL = os.getenv("SECUREVAULT_API", "http://127.0.0.1:8000")
TOKEN_PATH = os.path.expanduser("~/.securevault/token")

def save_token(token: str):
    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
    with open(TOKEN_PATH, "w") as f:
        f.write(token)

def load_token() -> str:
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH) as f:
            return f.read().strip()
    raise click.ClickException("Not logged in – run 'securevault login'")

def auth_headers():
    token = load_token()
    return {"Authorization": f"Bearer {token}"}

@click.group()
def cli():
    "SecureVault command‑line client"

@cli.command()
@click.option("--username", prompt=True)
@click.password_option(prompt="Master password", confirmation_prompt=True)
def register(username, password):
    "Register a new user"
    resp = requests.post(f"{API_URL}/register", params={"username": username, "master_password": password})
    if resp.ok:
        click.echo("Registration successful")
    else:
        click.echo(f"Error: {resp.text}", err=True)
        sys.exit(1)

@cli.command()
@click.option("--username", prompt=True)
@click.password_option(prompt="Master password")
def login(username, password):
    "Obtain an access token"
    data = {"grant_type": "password", "username": username, "password": password}
    resp = requests.post(f"{API_URL}/token", data=data)
    if resp.ok:
        token = resp.json()["access_token"]
        save_token(token)
        click.echo("Login successful – token stored")
    else:
        click.echo(f"Error: {resp.text}", err=True)
        sys.exit(1)

@cli.command()
@click.option("--service", prompt=True)
@click.option("--login", prompt=True)
@click.password_option(prompt="Password")
def add(service, login, password):
    "Add a new credential"
    payload = {"service": service, "login": login, "password": password}
    resp = requests.post(f"{API_URL}/credentials", json=payload, headers=auth_headers())
    if resp.ok:
        click.echo("Credential stored successfully")
    else:
        click.echo(f"Error: {resp.text}", err=True)
        sys.exit(1)

@cli.command()
@click.argument("service")
def get(service):
    "Retrieve a credential for SERVICE"
    resp = requests.get(f"{API_URL}/credentials/{service}", headers=auth_headers())
    if resp.ok:
        data = resp.json()
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(f"Error: {resp.text}", err=True)
        sys.exit(1)

@cli.command()
def health():
    "Check API health"
    resp = requests.get(f"{API_URL}/health")
    click.echo(resp.text)

if __name__ == "__main__":
    cli()
