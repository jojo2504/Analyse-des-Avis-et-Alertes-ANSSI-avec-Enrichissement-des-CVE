# What it does

This mini project aims to collect rss flux, extracting and enriching the CVEs with its internal data collected from different sources.

It features a webpage where one user can send the extracted CVEs to some emails by choice. 

> [!NOTE] 
All mails will be trapped by mailtrap

# Prerequisites:
Make sure a python virtual environment is sourced and that you have installed all needed dependencies (e.g., `pip install -r requirements.txt`)

# Running the project

You will need to:
- Create a mail trap account and put the password at `cve-manager/settings.py`
- Copy/Rename the `cve_manager/settings.py.example` to `cve_manager/settings.py.example`.
- Update the `username` and `password` for mailtrap.
- run `start.sh` or `start.bat` if the csv file (default example already in root directory) has already been computed, else:
  - `python main.py` to generate the csv file
  - `python manage.py import_cves` to import the csv file to the backend local database

> [!WARNING] 
Make sure the wifi/ethernet firewall isn't blocking any mail from being sent.
