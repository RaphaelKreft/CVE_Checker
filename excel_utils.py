import os
import csv
import openpyxl

"""
This file contains methods to read and write from/to csv and excel files. they dump and try to read a so
called software-dictionary which contains the following fields: key=swName, value=date_of_last_check
"""


def read_software_data(input_file: str, delimiter: str = "", excel=False):
    if not os.path.isfile(input_file):
        raise IOError(f"File {input_file} doesn't exist!")
    else:
        software_dict = {}
        with open(input_file, mode="r", encoding="utf-8") as f:
            if excel:
                workbook = openpyxl.load_workbook(input_file)
                ws = workbook.active
                for row in list(ws.iter_rows(values_only=True)):
                    software_dict[row[0]] = row[1]
            else:
                csv_reader = csv.reader(f, delimiter=delimiter)
                for row in csv_reader:
                    software_dict[str(row[0])] = row[1] if len(row) >= 2 else ""
        return software_dict


def dumb_updated_data(output_file, software_dict: dict, delimiter: str = ",", excel=False):
    if os.path.isfile(output_file):
        os.remove(output_file)
    if excel:
        wb = openpyxl.Workbook()
        sheet = wb.active
        for key, val in software_dict.items():
            sheet.append([key, val])
        wb.save(output_file)
    else:
        with open(output_file, mode='w') as f:
            csv_writer = csv.writer(f, delimiter=delimiter)
            for key in software_dict.keys():
                csv_writer.writerow([key, software_dict[key]])


#def _filter_and_parse(software_dict: dict):
#    for key, val in software_dict.items():
#        try:
#            software_dict[key] = datetime.datetime.strptime(val, "")
#        except Exception:
#            software_dict[key] = False


if __name__ == "__main__":
    # test read of data from excel sheet
    data = read_software_data("test.xlsx", excel=True)
    print(data)
    # test dump
    dumb_updated_data("output.xlsx", data, excel=True)
