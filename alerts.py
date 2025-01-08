import argparse
import os
import getpass
import yaml
import requests
import json
import sys
import time
from requests.auth import HTTPBasicAuth
import base64
from git import Repo

# Splunk config
splunk_host = "https://splunk.dreamcompany.cy:8089"
username = "admin"
headers = {"Content-Type": "application/x-www-form-urlencoded"}

alerts_repo_path = "./alerts"
defaults_file_path = "./defaults.yaml"

def get_splunk_admin_password():
    secret_file = os.getenv('SPLUNK_ADMIN')
    if not secret_file:
        raise EnvironmentError("SPLUNK_ADMIN environment variable is not set.")
    try:
        with open(secret_file, 'r') as file:
            password = file.read().strip()
            return password
    except FileNotFoundError:
        raise FileNotFoundError(f"Secret file '{secret_file}' does not exist.")
    except PermissionError:
        raise PermissionError(f"Secret file '{secret_file}' is not readable.")
    except Exception as e:
        raise Exception(f"An error occurred while reading the secret file: {e}")

password = get_splunk_admin_password()

#Load defaults.yaml
def load_defaults(defaults_path):
    if not os.path.exists(defaults_path):
        print(f"Defaults file not found at {defaults_path}. Proceeding without defaults.")
        return {}
    with open(defaults_path, "r") as f:
        try:
            defaults = yaml.safe_load(f)
            return defaults
        except yaml.YAMLError as e:
            print(f"Error parsing defaults.yaml: {e}")
            return {}

defaults = load_defaults(defaults_file_path)

#Get list of splunk alerts. Owned by admin
def get_splunk_alerts():
    endpoint = "/servicesNS/admin/search/saved/searches?search=(eai:acl.owner=admin)"
    url = f"{splunk_host}{endpoint}"
    params = {"output_mode": "json"}
    response = requests.get(
        url, params=params, auth=HTTPBasicAuth(username, password), verify=False
    )
    if response.status_code == 200:
        return [entry["name"] for entry in response.json()["entry"]]
    else:
        print(f"Failed to fetch alerts: {response.status_code}")
        print(response.text)
        return []

# Create alert
def create_alert(alert_name, alert_data):
    endpoint = "/servicesNS/admin/search/saved/searches"
    url = f"{splunk_host}{endpoint}"
    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        headers=headers,
        data=alert_data,
        verify=False,
    )
    if response.status_code == 201:
        print(f"Alert '{alert_name}' created successfully!")
    else:
        print(f"Failed to create alert '{alert_name}': {response.status_code}")

# Update alert if it is already exist
def update_alert(alert_name, alert_data):
    endpoint = f"/servicesNS/nobody/search/saved/searches/{alert_name}"
    url = f"{splunk_host}{endpoint}"

    # Remove key 'name'
    alert_data.pop("name", None)

    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        headers=headers,
        data=alert_data,
        verify=False,
    )
    if response.status_code == 200:
        print(f"Alert '{alert_name}' updated successfully!")
    else:
        print(f"Failed to update alert '{alert_name}': {response.status_code}")
#        print(response.text)

# Set ACL
def set_acl(alert_name, acl_data):
    endpoint = f"/servicesNS/admin/search/saved/searches/{alert_name}/acl"
    url = f"{splunk_host}{endpoint}"
    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        headers=headers,
        data=acl_data,
        verify=False,
    )
    if response.status_code == 200:
        print(f"ACL for alert '{alert_name}' set successfully!")
    else:
        print(f"Failed to set ACL for alert '{alert_name}': {response.status_code}")
#        print(response.text)

# Get changed files using Git
def get_changed_files(repo_path, base_commit, head_commit):
    repo = Repo(repo_path)
    diff = repo.git.diff('--name-only', base_commit, head_commit)
    return diff.splitlines()


# Get list of alerts from repo and alert content
def get_repo_alerts(changed_only=False, changed_files=None):
    repo_alerts = {}
    alert_folders = []
    for folder in os.listdir(alerts_repo_path):
        alert_path = os.path.join(alerts_repo_path, folder)
        if os.path.isdir(alert_path):
            alert_file = os.path.join(alert_path, "alert.yaml")
            if os.path.exists(alert_file):
                # Normalize file paths to a consistent format. With get_changed_files func
                normalized_alert_file = os.path.normpath(alert_file)
                normalized_changed_files = [os.path.normpath(file) for file in changed_files]

                if changed_only and normalized_alert_file not in normalized_changed_files:
                    continue

                alert_folders.append(folder)
                with open(alert_file, "r") as f:
                    alert_data = yaml.safe_load(f)
                    repo_alerts[folder] = alert_data
    return repo_alerts, alert_folders

# Prepare alert payload
def prepare_payload(alert_name, alert_data):
    payload = {
        "name": alert_name,
        "search": alert_data["search"],
        "cron_schedule": alert_data["cron_schedule"],
        "is_visible": True,
        "is_scheduled": True,
        "disabled": alert_data.get("disabled", False),
        "description": alert_data.get("description", ""),
        "alert_type": alert_data.get("alert_type", "number of events"),
        "alert_comparator": alert_data.get("alert_comparator", "greater than"),
        "alert_threshold": alert_data.get("alert_threshold", "0"),
        "alert.track": alert_data.get("alert.track", "0"),
        "alert.severity": alert_data.get("alert.severity", "3"),
        "alert.digest_mode": "false",
        "dispatch.earliest_time": alert_data.get("earliest_time", "-60m@m"),
        "dispatch.latest_time": "now",

    }
    # Configure alert actions
    default_actions = defaults.get("actions", {})

    if "actions" in alert_data:
        actions = []
        for action_name, action_details in alert_data["actions"].items():
            if action_details.get("enabled", False):
                actions.append(action_name)
                #
                default_action_params = default_actions.get(action_name, {})
                for param, default_value in default_action_params.items():
                    #
                    payload_key = param
                    #
                    payload[payload_key] = action_details.get(param, default_value)
                
                #
                for param, value in action_details.items():
                    if param not in default_action_params and param != "enabled":
                        payload[param] = value
        payload["actions"] = ",".join(actions)
    if "throttling" in alert_data:
        throttling = alert_data["throttling"]
        if throttling.get("suppress", False):
            payload["alert.suppress"] = True
            payload["alert.suppress.period"] = throttling.get("period", "60m")
            suppress_fields = throttling.get("fields", [])
            if suppress_fields:
                payload["alert.suppress.fields"] = ",".join(suppress_fields)

    # Add other fields from alert_data
    if "dispatch" in alert_data:
        for key, value in alert_data["dispatch"].items():
            payload[f"dispatch.{key}"] = value
    if "alert" in alert_data:
        for key, value in alert_data["alert"].items():
            payload[f"alert.{key}"] = value

    return payload

# Sync alerts
def sync_alerts(deploy_all=False):
    repo_alerts, repo_folders = get_repo_alerts(
        changed_only=not deploy_all,
        changed_files=get_changed_files(".", "HEAD~1", "HEAD")
    )
    splunk_alerts = get_splunk_alerts()

    for alert_name in repo_folders:
        alert_data = repo_alerts.get(alert_name, {})
        payload = prepare_payload(alert_name, alert_data)
        owner = alert_data.get("owner", "admin")
        acl_data = {
            "owner": owner,
            "sharing": alert_data.get("sharing", "global"),
            "perms.read": ",".join(alert_data["permissions"]["read"]),
            "perms.write": ",".join(alert_data["permissions"]["write"]),
        }

        if alert_name not in splunk_alerts:
            print(f"Creating alert: {alert_name}")
            create_alert(alert_name, payload)
            set_acl(alert_name, acl_data)
        else:
            print(f"Updating alert: {alert_name}")
            update_alert(alert_name, payload)
            set_acl(alert_name, acl_data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy Splunk alerts.")
    parser.add_argument("--deploy-all", action="store_true", help="Deploy all alerts.")
    parser.add_argument(
        "--deploy-changed-only", action="store_true", help="Deploy only changed alerts."
    )
    args = parser.parse_args()

    if args.deploy_all:
        sync_alerts(deploy_all=True)
    elif args.deploy_changed_only:
        sync_alerts(deploy_all=False)
    else:
        print("Specify either --deploy-all or --deploy-changed-only.")
