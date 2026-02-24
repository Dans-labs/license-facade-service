import os

import tomli
from dynaconf import Dynaconf

base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ["BASE_DIR"] = os.getenv("BASE_DIR", base_dir)

try:
    app_settings = Dynaconf(
        settings_files=["conf/settings.toml", "conf/*.yaml", "conf/.secrets.toml"],
        environments=True,
    )
except Exception as e:
    print(f"Error loading settings: {e}")
    app_settings = None  # Set to None if loading fails, code should handle this gracefully


def get_project_details(base_dir: str, keys: list):
    with open(os.path.join(base_dir, 'pyproject.toml'), 'rb') as file:
        package_details = tomli.load(file)
    poetry = package_details['project']
    return {key: poetry[key] for key in keys}