"""
GitHub App Authentication Service
Handles JWT auth, installation tokens, and GitHub API interactions for SBOMGuard.
"""
import os
import time
import jwt
import requests

# GitHub App configuration from environment variables
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY_PATH = os.getenv("GITHUB_PRIVATE_KEY_PATH", "vulnera-graybox.pem")


def _get_private_key() -> str:
    """Load the GitHub App private key from disk."""
    # Resolve relative paths from the backend directory
    key_path = GITHUB_PRIVATE_KEY_PATH
    if not os.path.isabs(key_path):
        key_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), key_path)

    if not os.path.exists(key_path):
        raise ValueError(
            f"GitHub Private Key not found at: {key_path}. "
            "Ensure GITHUB_PRIVATE_KEY_PATH is set in your environment."
        )

    with open(key_path, "r") as f:
        return f.read()


def generate_app_jwt() -> str:
    """
    Generate a JSON Web Token (JWT) to authenticate as the GitHub App.
    Tokens are valid for a maximum of 10 minutes.
    """
    if not GITHUB_APP_ID:
        raise ValueError("GITHUB_APP_ID is not set in the environment")

    private_key = _get_private_key()

    # Payload for GitHub App JWT
    now = int(time.time())
    payload = {
        "iat": now - 60,       # Issued at (allow 60s for clock drift)
        "exp": now + (10 * 60),  # Expires in 10 minutes (max allowed)
        "iss": GITHUB_APP_ID     # Issuer (the App ID)
    }

    # Encode the JWT using RS256 algorithm
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")
    return encoded_jwt


def get_installation_token(installation_id: str) -> str:
    """
    Exchange the App JWT for a specific installation access token.
    This token is scoped strictly to the repositories the user selected.
    """
    app_jwt = generate_app_jwt()

    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    response = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=headers
    )

    if response.status_code != 201:
        raise Exception(f"Failed to generate installation token: {response.status_code} - {response.text}")

    return response.json()["token"]


def list_accessible_repos(installation_token: str) -> list[dict]:
    """
    List all repositories that the user gave the app access to for this installation.
    """
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    response = requests.get(
        "https://api.github.com/installation/repositories",
        headers=headers
    )

    if response.status_code != 200:
        raise Exception(f"Failed to fetch repositories: {response.status_code} - {response.text}")

    return response.json().get("repositories", [])


def list_branches(installation_token: str, owner: str, repo: str) -> list[str]:
    """
    List all branches for a specific repository.
    """
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    response = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/branches",
        headers=headers
    )

    if response.status_code != 200:
        raise Exception(f"Failed to fetch branches: {response.status_code} - {response.text}")

    return [branch["name"] for branch in response.json()]
