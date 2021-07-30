"""
api.py: This file contains functions to query the API of NVD
"""

from datetime import datetime
import pytz
import requests

SEARCH_URL_SPECIFIC = 'https://services.nvd.nist.gov/rest/json/cve/1.0'
SEARCH_URL_MULTI = 'https://services.nvd.nist.gov/rest/json/cves/1.0'


def search_by_id(cve_id: str):
    """
    This method is not used currently but can later be modified to get information about specific cves.
    It takes a specific Vulnerability ID(CVE_Number) and returns a CVE Instance if a result is found.
    """
    data = _request_specific_by_id(cve_id)
    if ('message' in data.keys() and data['message'].contains('Unable to find vuln')) or data['totalResults'] == 0:
        raise NoDataReceivedError(f"No data for vce with id {cve_id}")
    else:
        return CveResultList(data)


def search_by_name_and_date(keyword: str, start_date: datetime = None):
    """
    This Method takes a keyword and a start_date which are the parameters for the search we initiate on NVD.
    It raises an error if no result was found else it returns the id and date of the latest cve found.
    """
    data = _request_multi(keyword, start_date)
    if data['totalResults'] == 0:
        raise NoDataReceivedError(f"No new data since {start_date} for search with with keyword {keyword}")
    else:
        return CveResultList(data)


def _request_specific_by_id(cve_id):
    response = requests.get(url=f'{SEARCH_URL_SPECIFIC}/{cve_id}')
    return response.json()


def _request_multi(keyword: str, start_date: datetime):
    if start_date is None:
        pars = {'keyword': keyword}
    else:
        pars = {'keyword': keyword, 'pubStartDate': start_date.strftime("%Y-%m-%dT%00:00:00:000")}
    response = requests.get(url=SEARCH_URL_MULTI, params=pars)
    return response.json()


class Cve:
    """
    This class is an abstraction of a CVE-Entry. In this Version just the necessary Data is included.
    """
    def __init__(self, cve_id, published_date, last_modified_date, severity):
        self.cve_id = cve_id
        self.published_date = published_date
        self.last_modified_date = last_modified_date
        self.severity = severity

    def __str__(self):
        return f"CVE: {self.cve_id}\n- published_date: {self.published_date}\n" \
               f"- last_modified: {self.last_modified_date}\n- severity: {self.severity}"

    @staticmethod
    def result_to_cve(result_json):
        mod_date = datetime.strptime(result_json['lastModifiedDate'], "%Y-%m-%dT%H:%MZ")
        pub_date = datetime.strptime(result_json['publishedDate'], "%Y-%m-%dT%H:%MZ")
        cve_id = result_json['cve']['CVE_data_meta']['ID']
        severity = result_json['impact']['baseMetricV2']['severity']
        return Cve(cve_id, pub_date, mod_date, severity)


class CveResultList:
    """
    Instances of this class are used to represent/store lists of results received by the api.
    """
    def __init__(self, json_result):
        self.results = []
        self.num_results = None
        if json_result is not None:
            self._parse_json(json_result)

    def get_latest(self):
        """
        This method returns the most current CVE from the list of results
        """
        if self.results is not None:
            return max(self.results, key=lambda x: x.published_date)

    def _parse_json(self, json_result):
        """
        This method takes the complete result_json from the api and parse it.
        """
        self.num_results = json_result["totalResults"]
        for cve_json in json_result["result"]["CVE_Items"]:
            self.results.append(Cve.result_to_cve(cve_json))


class NoDataReceivedError(Exception):
    def __init__(self, message):
        super().__init__(f"There was no data received for the vulnerability: \n{message}")


if __name__ == "__main__":
    # test search by ID
    #test_res = search_by_id('CVE-2015-5611')
    #print(test_res)
    # test search by keyword & date
    test_res_2 = search_by_name_and_date('maple', datetime(year=2017, month=6, day=12, hour=12, second=12, minute=12,
                                                           tzinfo=pytz.timezone("Europe/Berlin")))
    print(test_res_2)

