import sys
import requests
import getopt
import json
import urllib.parse
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import time
import xml.etree.ElementTree as ET  # for parsing XML

from veracode_api_signing.credentials import get_credentials

class NoExactMatchFoundException(Exception):
    message=""
    def __init__(self, message_to_set):
        self.message = message_to_set

    def get_message(self):
        return self.message

json_headers = {
    "User-Agent": "Sbom Extractor - Python Script",
    "Content-Type": "application/json"
}

def print_help():
    """Prints command line options and exits"""
    print("""py veracode-sbom.py -a <application_name> -f <file_name> [-d]
        Extracts an SBOM from the latest scan for the application named <application_name> and saves it to a file called <file_name>
""")
    sys.exit()

def url_encode(value_to_encode):
    return urllib.parse.quote(value_to_encode, safe='')

def find_exact_match(list, to_find, outer_field_name, field_name):
    for index in range(len(list)):
        element = list[index]
        if not outer_field_name or outer_field_name in element:
            inner_element = element[outer_field_name] if outer_field_name else element
            if field_name in inner_element:
                if inner_element[field_name] == to_find:
                    return element
    print(f"Unable to find a member of list with {field_name} equal to {to_find}")
    raise NoExactMatchFoundException(f"Unable to find a member of list with {field_name} equal to {to_find}")

def url_encode_with_plus(a_string):
    return urllib.parse.quote_plus(a_string, safe='').replace("&", "%26")

def get_error_node_value(body):
    inner_node = ET.XML(body)
    if inner_node.tag == "error" and not inner_node == None:
        return inner_node.text
    else:
        return ""

def get_application_guid(api_base, application_name, verbose):
    path = f"{api_base}appsec/v1/applications?name={url_encode(application_name)}"
    if verbose:
        print(f"Calling: {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)
    data = response.json()

    if response.status_code == 200:
        if verbose:
            print(data)
        if "_embedded" in data and len(data["_embedded"]["applications"]) > 0:
            return find_exact_match(data["_embedded"]["applications"], application_name, "profile", "name")["guid"]
        else:
            print(f"ERROR: No application named '{application_name}' found")
            return f"ERROR: No application named '{application_name}' found"
    print(f"ERROR: trying to get application named {application_name}")
    print(f"ERROR: code: {response.status_code}")
    print(f"ERROR: value: {data}")
    sys.exit(1)

def get_workspace_guid(api_base, workspace_name, verbose):
    path = f"{api_base}srcclr/v3/workspaces?filter%5Bworkspace%5D={url_encode(workspace_name)}"
    if verbose:
        print(f"Calling: {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)
    data = response.json()

    if response.status_code == 200:
        if verbose:
            print(data)
        if "_embedded" in data and len(data["_embedded"]["workspaces"]) > 0:
            return find_exact_match(data["_embedded"]["workspaces"], workspace_name, None, "name")["id"]
        else:
            print(f"ERROR: No workspace named '{workspace_name}' found")
            return f"ERROR: No workspace named '{workspace_name}' found"
    print(f"ERROR: trying to get workspace named {workspace_name}")
    print(f"ERROR: code: {response.status_code}")
    print(f"ERROR: value: {data}")
    sys.exit(1)

def get_project_guid(api_base, workspace_guid, project_name, verbose):
    path = f"{api_base}srcclr/v3/workspaces/{workspace_guid}/projects?search={url_encode(project_name)}"
    if verbose:
        print(f"Calling: {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)
    data = response.json()

    if response.status_code == 200:
        if verbose:
            print(data)
        if "_embedded" in data and len(data["_embedded"]["projects"]) > 0:
            return find_exact_match(data["_embedded"]["projects"], project_name, None, "name")["id"]
        else:
            print(f"ERROR: No project named '{project_name}' found in the workspace")
            return f"ERROR: No project named '{project_name}' found in the workspace"
    print(f"ERROR: trying to get workspace named {project_name}")
    print(f"ERROR: code: {response.status_code}")
    print(f"ERROR: value: {data}")
    sys.exit(1)

def get_sbom_for_project(api_base, workspace_name, project_name, file_name, verbose):
    workspace_guid=get_workspace_guid(api_base, workspace_name, verbose)
    if not workspace_guid:
        sys.exit(1)
    project_guid=get_project_guid(api_base, workspace_guid, project_name, verbose)
    if not project_guid:
        sys.exit(1)

    path = f"{api_base}srcclr/sbom/v1/targets/{project_guid}/cyclonedx?type=agent"
    if verbose:
        print(path)

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)

    if verbose:
        print(f"status code {response.status_code}")
        body = response.json()
        if body:
            print(body)
    if response.status_code == 200:
        print("Successfully extracted the sbom.")
        body = response.json()
        if verbose and body:
            print(body)
        json_object = json.dumps(body, indent=2)
 
        with open(file_name, "w") as outfile:
            outfile.write(json_object)
    else:
        body = response.json()
        if (body):
            return f"Unable to create get sbom: {response.status_code} - {body}"
        else:
            return f"Unable to create get sbom: {response.status_code}"

def get_sbom_for_application(api_base, application_name, file_name, verbose):
    application_guid=get_application_guid(api_base, application_name, verbose)
    if not application_guid:
        sys.exit(1)

    path = f"{api_base}srcclr/sbom/v1/targets/{application_guid}/cyclonedx?type=application"
    if verbose:
        print(path)

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)

    if verbose:
        print(f"status code {response.status_code}")
        body = response.json()
        if body:
            print(body)
    if response.status_code == 200:
        print("Successfully extracted the sbom.")
        body = response.json()
        if verbose and body:
            print(body)
        json_object = json.dumps(body, indent=2)
 
        with open(file_name, "w") as outfile:
            outfile.write(json_object)
    else:
        body = response.json()
        if (body):
            return f"Unable to create get sbom: {response.status_code} - {body}"
        else:
            return f"Unable to create get sbom: {response.status_code}"

def get_api_base():
    api_key_id, api_key_secret = get_credentials()
    api_base = "https://api.veracode.{instance}/"
    if api_key_id.startswith("vera01"):
        return api_base.replace("{instance}", "eu", 1)
    else:
        return api_base.replace("{instance}", "com", 1)

def main(argv):
    """Extracts an SBOM for a project or application"""
    global failed_attempts
    global last_column
    excel_file = None
    try:
        verbose = False
        application_name = ''
        file_name = ''
        workspace = ''
        project = ''

        opts, args = getopt.getopt(argv, "hdf:a:w:p:", ["file_name=", "application_name=", "workspace=", "project="])
        for opt, arg in opts:
            if opt == '-h':
                print_help()
            if opt in ('-f', '--file_name'):
                file_name = arg
            if opt == '-d':
                verbose = True
            if opt in ('-a', '--application_name'):
                application_name=arg
            if opt in ('-w', '--workspace'):
                workspace=arg
            if opt in ('-p', '--project'):
                project=arg

        api_base = get_api_base()
        if file_name and application_name:
            get_sbom_for_application(api_base, application_name, file_name, verbose)
        elif file_name and workspace and project:
            get_sbom_for_project(api_base, workspace, project, file_name, verbose)
        else:
            print_help()
    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)
    finally:
        if excel_file:
            excel_file.save(filename=file_name)


if __name__ == "__main__":
    main(sys.argv[1:])
