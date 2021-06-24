"""
api.py: This file contains functions to query the API of NVD
"""

import json
import requests

SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"


def query_specific_entry(cve_id):
    """
    This method is not used currently but can later be modified to get information about specific cves
    """
    response = requests.get(url=f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}")
    data = response.json()
    if ('message' in data.keys() and data['message'].contains('Unable to find vuln')) or data['totalResults'] == 0:
        raise IOError(f"No data for vce with id {cve_id}")
    else:
        latest = data['result']['CVE_Items'][0]
        date = latest['lastModifiedDate']
        return date


def search_for_entries(keyword, startdate):
    """
    This Method takes a keyword and a startdate which are the parameters for the search we initiate on NVD.
    It raises an error if no result was found else it returns the id and date of the latest cve found.
    """
    if startdate == "":
        pars = {"keyword":keyword}
    else:
        pars = {"keyword":keyword, "pubStartDate":startdate}

    response = requests.get(url=SEARCH_URL, params=pars)
    data = response.json()
    if data['totalResults'] == 0:
        raise IOError(f"No new data since {startdate} for search with with keyword {keyword}")
    else:
        latest = data['result']['CVE_Items'][0]
        date = latest['lastModifiedDate']
        return (latest['CVE_data_meta']['ID'] , date)