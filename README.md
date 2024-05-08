# Veracode Get SBOM

## Overview

This script allows for extracting, from the Veracode Platform, the SBOM for a Project or Application

## Installation

Clone this repository:

    git clone https://github.com/cadonuno/Veracode-Get-Sbom.git

Install dependencies:

    cd Veracode-Get-Sbom
    pip install -r requirements.txt

### Getting Started

It is highly recommended that you store veracode API credentials on disk, in a secure file that has 
appropriate file protections in place.

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>
    
### Running the script
    py veracode-sbom.py -a <application_name> -f <file_to_save> [-d]
        Extracts an SBOM from the latest scan for the application named <application_name>

    py veracode-sbom.py -w <workspace_name> -p <project_name> -f <file_to_save> [-d]
        Extracts an SBOM from the latest scan for the application named <application_name>


If a credentials file is not created, you can export the following environment variables:   

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    py veracode-sbom.py -a <application_name> [-d]

## License

[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

See the [LICENSE](LICENSE) file for details
