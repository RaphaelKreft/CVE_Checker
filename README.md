# CVE_Checker

In the first planned Version, this is a simple Python script, that takes a csv formatted file(.csv or .xlsx) and checks 
for new entries in the CVE-Register from https://nvd.nist.gov/.

## How It works
The Script reads the given file. Based on columns you need to name for "Name" and "Last-Vulnerability-Check" the script
uses the self-made python module to query the API from NVD.
The results are printed to the commandline.

## Usage
In this first commandline based version the user gives the input-parameters via commandline arguments.

'''
python3 cve_checker.py -i sampleInput.csv -n namecolumn-number -d datecolumn-number
'''
