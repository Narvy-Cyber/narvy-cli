import json
import os
import stat

CONFIG_DIR = os.path.expanduser("~/.narvy")
CREDENTIALS_PATH = os.path.join(CONFIG_DIR, "credentials")


def save_token(token, email, plan):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    # 0600 at creation so the token file is never briefly readable by others.
    fd = os.open(CREDENTIALS_PATH, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"token": token, "email": email, "plan": plan}, f)
    os.chmod(CREDENTIALS_PATH, stat.S_IRUSR | stat.S_IWUSR)


def _env(name):
    """Read a NARVY_<name> environment override."""
    return os.environ.get(f"NARVY_{name}", "").strip()


def load_credentials():
    # NARVY_TOKEN overrides the stored file for CI / parallel use.
    env_token = _env("TOKEN")
    if env_token:
        return {
            "token": env_token,
            "email": _env("EMAIL"),
            "plan": _env("PLAN"),
        }
    if not os.path.exists(CREDENTIALS_PATH):
        return None
    with open(CREDENTIALS_PATH) as f:
        return json.load(f)


def logout():
    if os.path.exists(CREDENTIALS_PATH):
        os.remove(CREDENTIALS_PATH)
