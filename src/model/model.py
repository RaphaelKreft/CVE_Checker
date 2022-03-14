"""
model.py: This class contains classes that represent the "model" part of a MVC Pattern. The main classes can be used to get and safe data.
"""


# This class represents an Interface for which methods a Model should have
class ModelInterface(object):
    def get_software_data_by_id(self, ID):
        pass

    def update_software_data_by_id(self, ID, values):
        pass

    def get_software_IDs(self):
        pass


class ModelError(Exception):
    pass
