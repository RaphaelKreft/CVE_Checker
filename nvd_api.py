"""
nvd_api.py: This file contains functions to query the REST API of NVD for CVE
"""

from datetime import datetime, timedelta
import requests
import logging

logging.warning("URL3LIB - Warnings are disabled!")
requests.packages.urllib3.disable_warnings()


class NvdApi:
    SEARCH_URL_SPECIFIC = 'https://services.nvd.nist.gov/rest/json/cve/1.0'
    SEARCH_URL_MULTI = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

    def search_by_id(self, cve_id: str):
        """
        This method is not used currently but can later be modified to get information about specific cves.
        It takes a specific Vulnerability ID(CVE_Number) and returns a CVE Instance if a result is found.
        """
        data = self._request_specific_by_id(cve_id)
        if ('message' in data.keys() and data['message'].contains('Unable to find vuln')) or data['totalResults'] == 0:
            raise APIError(f"No data for cve with id {cve_id}. (resultcount = 0)")
        else:
            return CveResultList(data)

    def search_by_name_and_date(self, keyword: str, start_date: datetime = None):
        """
        This Method takes a keyword and a start_date which are the parameters for the search we initiate on NVD.
        This method should perform a query in a date range from given start_date up to current time. Therefor the
        range is split in parts of max 120 days to be able to work with the NVD API. If a query fails, an APIError is
        raised and this search is aborted.
        """
        now = datetime.now()
        max_delta = timedelta(days=120)
        ranges = []
        # prepare date-ranges of max 120 days to be able to query NVD API
        my_delta = now - start_date
        curr_date = start_date
        while my_delta > max_delta:
            ranges.append((curr_date, curr_date + max_delta))
            curr_date += max_delta
            my_delta = now - curr_date
        ranges.append((curr_date, now))
        # perform queries
        results = []
        for start, end in ranges:
            results.append(self._name_date_query(keyword, start, end))
        return sum(results)

    def _request_specific_by_id(self, cve_id: str):
        """
        Request data for a specific CVE-ID, returns the answer json
        """
        response = requests.get(url=f'{self.SEARCH_URL_SPECIFIC}/{cve_id}', verify=False)
        return response.json()

    def _name_date_query(self, keyword: str, start_date: datetime = None, end_date: datetime = None):
        """
        build a request for the nvd api, by using date and keyword parameters. Then sends request and returns result
        as json
        """
        # if start_date not given, just search for keyword, else include start_date as search paramete
        pars = {'keyword': keyword, 'pubStartDate': start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00"),
                'pubEndDate': end_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00")}
        response = requests.get(url=self.SEARCH_URL_MULTI, params=pars, verify=False)
        logging.info(f"requestURL: {response.url}")
        if response.ok:
            return response.json()
        else:
            raise APIError(f"API call for {keyword} not 'ok': {response.json()} \n\n",)


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
        """
        Method to make an CVe instance from a json received by the api
        """
        mod_date = datetime.strptime(result_json['lastModifiedDate'], "%Y-%m-%dT%H:%MZ")
        pub_date = datetime.strptime(result_json['publishedDate'], "%Y-%m-%dT%H:%MZ")
        cve_id = result_json['cve']['CVE_data_meta']['ID']
        if result_json['impact'] == {}:
            severity = "UNKNOWN"
        else:
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

    def __init__(self, results: list):
        """
        Constructor for directly storing results. Used when adding.
        """
        self.results = results

    def get_latest(self):
        """
        This method returns the most current CVE from the list of results
        """
        if self.results is not None:
            return max(self.results, key=lambda x: x.published_date)

    def get_cve_id_list(self):
        """
        Returns a list of all ids of CVE's in the result-list of this instance
        """
        return [cve.cve_id for cve in self.results]

    def get_max_severity(self):
        """
        Finds the Cve with the highest severity and returns this severity.
        Returns None when result-list of cve's is empty.
        """
        if not self.results:
            return None
        return max(self.results, key=self._severity_ranking).severity

    def _parse_json(self, json_result):
        """
        This method takes the complete result_json from the api and parse it.
        """
        self.num_results = json_result["totalResults"]
        for cve_json in json_result["result"]["CVE_Items"]:
            self.results.append(Cve.result_to_cve(cve_json))

    def __add__(self, other):
        """
        Adding up Instances of this class means bulding a union of the result lists.
        This union will be saved in self object
        """
        merged_results = self.results
        for o in other.results:
            if o.cve_id not in self.get_cve_id_list():
                merged_results.append(o)
        return CveResultList(merged_results)

    @staticmethod
    def _severity_ranking(cve):
        """
        Takes a cve object and returns a number according to the severity of the CVE.
        This function is meant to be used as helper to be able to rank the cve's by their severity.
        """
        severities = {"UNKNOWN": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return severities[cve.severity]


class APIError(Exception):
    """
    Exception-class to represent an Error within the operation of an NvdApi instance.
    This class gets a message and logs it
    """

    def __init__(self, message):
        super().__init__(f"APIError: {message}")
        logging.error(f"APIError: {message}")
