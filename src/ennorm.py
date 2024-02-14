from sofahutils import logger


class EnNorm:
    """
    Class to enrich and normalize date for the SOFAH system.
    Here especially the data from the recon module is enriched and normalized. 
    """

    def __init__(self, config_path:str, logger:logger):
        self.config = config_path
        self.logger = logger
        self.logger.debug("EnNorm initialized")

    def enrich(self, data):
        """
        Enrich the data with the data from the recon module.
        """
        self.logger.debug("Enriching data")
        return data

    def normalize(self, data):
        """
        Normalize the data from the recon module.
        """
        self.logger.debug("Normalizing data")
        return data