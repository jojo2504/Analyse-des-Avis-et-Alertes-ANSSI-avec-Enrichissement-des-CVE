# What it does

This mini project aims to collect rss flux, extracting and enriching the CVEs with its internal data collected from different sources.

It features a webpage where one user can send the extracted CVEs to some emails by choice. 

> [!NOTE] 
All mails will be trapped by mailtrap

# Running the project

You will need to:
- Create a mail trap account and put the password at `cve-manager/settings.py`
- run `start.sh` or `start.bat` if the csv file has already been computed, else:
  - `python main.py` to generate the csv file
  - `python manage.py import_cves` to import the csv file to the backend local database

> [!WARNING] 
Make sure the wifi/ethernet firewall isn't blocking any mail from being sent.
