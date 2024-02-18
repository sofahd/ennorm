from sofahutils import SofahLogger, DockerCompose
from services import PortSpoofService, LogApiService



class Dockerizer:
    """
    This class implements a Dockerizer, it takes the normalized data and creates a docker-compose.yml, and configuration files for docker containers.
    Each container has to be implemented in the services pip-module.
    """


    def __init__(self, norm_data:dict, output_path:str, logger:SofahLogger, token:str) -> None:
        """
        This is the constructor of the Dockerizer class.

        ---
        :param norm_data: The normalized data.
        :type norm_data: dict
        :param output_path: The path to the output directory.
        :type output_path: str
        :param logger: The logger instance.
        :type logger: SofahLogger
        :param token: The token for the logger.
        :type token: str
        """

        self.norm_data = norm_data
        self.output_path = output_path
        self.logger = logger
        self.token = token


    