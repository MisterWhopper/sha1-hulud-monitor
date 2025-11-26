import requests
from configparser import ConfigParser
from typing import Optional
import pathlib
import urllib.parse
import json
import base64
import re

BASE_DIR = pathlib.Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.ini"
TOTAL_PAGES_RE = re.compile(r'page=(\d+)>;\s*rel="last"')

def load_secrets(config: ConfigParser) -> Optional[dict[str, str]]:
    from infisical_sdk import InfisicalSDKClient
    inf_creds = config["Secrets"]
    client = InfisicalSDKClient(host=inf_creds.get("INF_BASE_URL", ""))
    client.auth.universal_auth.login(
        client_id=inf_creds.get("INF_CLIENT_ID", ""),
        client_secret=inf_creds.get("INF_CLIENT_SECRET", "")
    )
    secrets = client.secrets.list_secrets(
            project_id=inf_creds.get("INF_PROJECT_ID", ""),
            environment_slug=inf_creds.get("INF_ENVIRONMENT", "dev"),
            secret_path=inf_creds.get("INF_SECRET_PATH", "/")
    )
    # Convert to dictionary for easier lookup
    return {s.secretKey: s.secretValue for s in secrets.secrets}


def get_github_search_results(config: ConfigParser, secret_data=None):
    request_data = urllib.parse.quote_plus(config["General"]["GH_SEARCH_QUERY"])
    full_query = f"{config['General']['GH_BASE_URL']}/search/repositories?q={request_data}"
    page_number = 1
    should_continue = True
    if secret_data is not None:
        headers = {"Authorization": f"Bearer {secret_data.get('API_Key')}"}
    else:
        headers = None
    try:
        with requests.Session() as session:
            while should_continue:
                results = session.get(full_query, headers=headers)
                if results.status_code != 200:
                    yield None
                total_pages_raw = re.search(TOTAL_PAGES_RE, results.headers.get("Link", ""))
                if total_pages_raw is not None:
                    total_pages = total_pages_raw.groups()[0]
                else:
                    total_pages = "?"
                print(f"Parsing page {page_number}/{total_pages} of results...")
                yield results.text
                # if there's a 'link' header in the reply, we have more pages to pull
                if results.headers.get("Link") is not None and "last" in results.headers.get("Link"):
                    page_number += 1
                    full_query = f"{config['General']['GH_BASE_URL']}/search/repositories?q={request_data}&page={page_number}"
                else:
                    should_continue = False
    except:
        yield None
    finally:
        print("Finished!")

def try_get_environment_from_name(full_name: str):
    url = f"https://raw.githubusercontent.com/{full_name}/refs/heads/main/environment.json"
    results = requests.get(url)
    if results.status_code != 200:
        return None
    return results.text

def process_data(item: dict):
    try:
        project_name = item["full_name"]
        environment_data = try_get_environment_from_name(item["full_name"])
        if environment_data is None:
            print(f"[WARNING] - Could not find environment data for '{item['full_name']}'; skipping...")
            return None
        stage1 = base64.b64decode(environment_data.encode("utf-8"))
        stage2 = base64.b64decode(stage1)
        final_data = json.loads(stage2.decode("utf-8"))
        package_name = final_data["environment"].get("npm_package_name")
        package_version = final_data["environment"].get("npm_package_version")
        if package_name is None or package_version is None:
            print(f"[ERROR] - Could not find npm package information in environment variables for '{project_name}'")
            return None
        print(f"\tProject '{item['full_name']}':\t\t{package_name}:{package_version}")
        return (project_name, f"{package_name}:{package_version}", item["created_at"])
    except:
        print(f"[ERROR] - Unexpected error while processing data for project '{item.get("full_name", "N/A")}'; skipping...")
        return None

def main():
    config = ConfigParser()
    result_data = {"skipped": []}
    if CONFIG_PATH.exists() and CONFIG_PATH.is_file():
        config.read(str(CONFIG_PATH))

    if "Secrets" in config.sections():
        secret_data = load_secrets(config)
    else:
        secret_data = None
    try:
        for search_results in get_github_search_results(config, secret_data):
            if search_results is None:
                break
            results = json.loads(search_results)
            for item in results["items"]:
                post_processing = process_data(item)
                if post_processing is None:
                    result_data["skipped"].append(item["full_name"])
                    continue
                project_name, package_slug, created_at = post_processing
                if package_slug not in result_data.keys():
                    result_data[package_slug] = []
                result_data[package_slug].append({"project": project_name, "created_at": created_at})

    except Exception as err:
        print(str(err))
    finally:
        with open(config["General"]["OUTPUT_FILE"], "w+") as fout:
            as_json = json.dumps(result_data, indent=4)
            fout.write(as_json)

if __name__ == "__main__":
    main()
