"""
Controller.py: contains the application_logic of this application
"""
import enum
import logging

from .model import Database, ModelError
from .web import get_page_html
from .hasher import hash


class Controller:
    def __init__(self):
        self.model = None

    def load_model(self, path):
        """
        Tries to load a model for this controller
        """
        try:
            self.model = Database(path)
        except ModelError as m_error:
            logging.error(str(m_error))

    def all_software(self, verbose=True):
        """
        Returns Information about all Software available in the model.
        params: verbose     boolean     if given, function will just return id, name pairs
        """
        software_ids = self.model.get_software_IDs()
        sw_data = [self.model.get_software_data_by_id(ID) for ID in software_ids]
        if verbose:
            return [(entry[0], entry[1]) for entry in sw_data]
        else:
            return sw_data

    def run_eula_check(self, targets=None):
        """
        Checks if EULA has changed or not for all Software, where eula URL is present.
        A EULA counts as changed, when before no hash was given. (First check of url).
        If no targets list is given, just perform check on all Software.

        @param: targets     If a list of targets is given, the check will run on this list
        """
        if targets and type(targets) == list:
            for target in targets:
                pass
        else:
            # run check on complete software-list
            all_software = self.model.get_software_IDs()
            for software_id in all_software:
                sw_data = self.model.get_software_data_by_id(software_id)
                result_code = self._perform_single_check(sw_data)
                # TODO: What to do with result_code Just Print out and/or write to model
                logging.info(f"Result {sw_data[1]}: {result_code.name}")

    def _perform_single_check(self, software_data_single):
        """
        Performs EULA Check and writes back result to the model
        """
        # extract values of interest
        eula_url = software_data_single[2]
        old_hash = software_data_single[3]
        ID = software_data_single[0]

        try:
            current_hash = hash(get_page_html(eula_url), 'MD5')
        except IOError as err:
            logging.info(f"The eula_url {eula_url} could not be reached...")
            if old_hash:
                return ResultCodes.EULA_URL_PROBABLY_CHANGED
            else:
                return ResultCodes.EULA_URL_NOT_REACHABLE

        if old_hash:
            # compare old with current hash
            similar = (old_hash == current_hash)
            # update database to new hash
            self.model.update_software_data_by_id(ID, {'EULA_HASH': current_hash})
            if similar:
                return ResultCodes.EULA_HASH_SIMILAR
            else:
                return ResultCodes.EULA_HASH_DIFFERENT
        else:
            self.model.update_software_data_by_id(ID, {'EULA_HASH': current_hash})
            return ResultCodes.INITIAL_HASH_SUCCESSFUL


class ResultCodes(enum.Enum):
    EULA_URL_NOT_REACHABLE = -1
    EULA_URL_PROBABLY_CHANGED = -2
    EULA_HASH_DIFFERENT = -3
    INITIAL_HASH_SUCCESSFUL = 1
    EULA_HASH_SIMILAR = 2
