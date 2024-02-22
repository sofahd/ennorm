from sofahutils import SofahLogger, DockerCompose, DockerComposeService
from services import PortSpoofService, LogApiService, ApiHoneypot, NginxHoneypot



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
        self.regex_placeholders = self.norm_data.get("regex_and_placeholder")


    def create_docker_compose(self) -> None:
        """
        This method creates the docker-compose.yml file.
        But first it creates the services.

        ---
        """

        services = []
        services.append(LogApiService(name="log_api", port=50005, token=self.token, log_folder_path="./log_folder"))
        for key, data in self.norm_data.items():
            if "poof" in key:
                services.append(PortSpoofService(name=key, port=data["port"], banner=data["banner"], mode=data["mode"], log_api_url="http://log_api:50005", token=self.token, log_container_name="log_api"))
            elif "api" in key:
                services.extend(self._create_api_services(data=data, name=key))
            
            
        
        dc = DockerCompose(services=services)

        list_of_dc_lines = dc.dump()

        with open(f"{self.output_path}/docker-compose.yml", "w") as f:
            for line in list_of_dc_lines:
                f.write(line + "\n")
        
        for service in services:
            service.download_repo()



    def _create_api_services(self, data:dict, name:str) -> list[DockerComposeService]:
        """
        This method creates the services for the api honeypot service.
        It is excluded from the create_docker_compose method, because it is a bit more complex.
    
        ---
        :param data: The data for the api honeypot service.
        :type data: dict
        :param name: The name of the service.
        :type name: str
        """

        services = []

        nginx_conf = data.get("nginx")
        port = data.get("port")
        endpoints = data.get("endpoints")
        network_name = f"{name}_net"
        data["placeholders"] = self.regex_placeholders

        if not nginx_conf or not port or not endpoints:
            raise ValueError("The data for the api honeypot service is not complete.")
        

        services.append(NginxHoneypot(name=f"{name}_nginx", port=port, nginx_config=nginx_conf, token=self.token, nginx_api_net_name=network_name, api_container_name=f"{name}_api"))
        services.append(ApiHoneypot(name=f"{name}_api", ext_port=port, answerset=data, token=self.token, nginx_api_net_name=network_name, log_api_url="http://log_api:50005", log_container_name="log_api"))

        return services