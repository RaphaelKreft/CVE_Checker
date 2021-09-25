import os
import csv

from openpyxl import Workbook, load_workbook
from openpyxl.worksheet.table import Table, TableStyleInfo

"""
This file contains methods to read and write from/to csv and excel files. they dump and try to read a so
called software-dictionary which contains the following fields: key=swName, value=date_of_last_check
"""


def read_software_data(input_file: str, name_col: int, date_col: int, delimiter: str = "", excel=False):
    """
    This function reads the software-data from a file. For this application just the name of the software and the last
    date of security check matters.
    """
    if not os.path.isfile(input_file):
        raise IOError(f"File {input_file} doesn't exist!")
    else:
        software_data = {}
        with open(input_file, mode="r", encoding="utf-8") as f:
            if excel:
                workbook = load_workbook(input_file)
                ws = workbook.active
                table = ws.tables.values()[0]  # here we assume that just one table in the right format exists
                software_data = ws[table.ref]
            else:
                csv_reader = csv.reader(f, delimiter=delimiter)
                for row in csv_reader:
                    software_data[str(row[name_col])] = row[date_col] if len(row) >= 2 else ""
        return software_data


def dumb_updated_data(output_file, software_list: list, delimiter: str = ",", excel=False):
    """
    This method writes the information regarding all software back into a file.
    """
    # delete existing file
    if os.path.isfile(output_file):
        os.remove(output_file)
    # create new file and write to it
    if excel:
        wb = Workbook()
        sheet = wb.active
        # create raw data
        sheet.append(["Name", "Last check", "New Items", "Highest severity"])
        for row in software_list:
            sheet.append(row)
        # make table out of it
        tab = Table(displayName="CVE_Info_Table", ref=f"A1:D{len(software_list)}")
        style = TableStyleInfo(name="TableStyleMedium9", showFirstColumn=False,
                               showLastColumn=False, showRowStripes=True, showColumnStripes=True)
        tab.tableStyleInfo = style
        sheet.add_table(tab)
        wb.save(output_file)
    else:
        with open(output_file, mode='w') as f:
            csv_writer = csv.writer(f, delimiter=delimiter)
            csv_writer.writerow(["Name", "Last check", "New Items", "Highest severity"])
            for row in software_list:
                csv_writer.writerow(row)


# def _filter_and_parse(software_dict: dict):
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
