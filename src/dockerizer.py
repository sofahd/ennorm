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


    def create_docker_compose(self) -> None:
        """
        This method creates the docker-compose.yml file.
        But first it creates the services.

        ---
        """

        services = []

        for key, data in self.norm_data.items():
            if "poof" in key:
                services.append(PortSpoofService(name=key, port=data["port"], banner=data["banner"], mode=data["mode"], log_api_url="http://log_api:50005", token=self.token, log_container_name="log_api"))
            elif "api" in key:
                #services.append()
                pass
        
        dc = DockerCompose(services=services)

        list_of_dc_lines = dc.dump()

        with open(f"{self.output_path}/docker-compose.yml", "w") as f:
            for line in list_of_dc_lines:
                f.write(line + "\n")
        
        for service in services:
            service.create_config_files(self.output_path)

