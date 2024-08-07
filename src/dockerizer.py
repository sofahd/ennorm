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
            if "poof" in key and data.get("mode") != None:
                services.append(PortSpoofService(name=key, port=data["port"], banner=data["banner"], mode=data["mode"], log_api_url="http://log_api:50005", token=self.token, log_container_name="log_api"))
            elif "api" in key:
                services.extend(self._create_api_services(data=data, name=key))
        
        dc = DockerCompose(services=services)
        dc.write_to_file(f"{self.output_path}/docker-compose.yml")
        dc.download_all_repos(self.output_path)



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
        service_version = data.get("service_version", "none")
        ssl_info = data.get("ssl", None)
        subject_info = ssl_info.get("subject", None) if ssl_info else None
        cn = subject_info.get("CN", None) if subject_info else None
        c = subject_info.get("C", None) if subject_info else None
        st = subject_info.get("ST", None) if subject_info else None
        l = subject_info.get("L", None) if subject_info else None
        o = subject_info.get("O", None) if subject_info else None
        ou = subject_info.get("OU", None) if subject_info else None


        data["placeholders"] = self.regex_placeholders

        if not nginx_conf or not port or not endpoints:
            raise ValueError("The data for the api honeypot service is not complete.")
        
        services.append(ApiHoneypot(name=f"{name}_api", ext_port=port, answerset=data, token=self.token, nginx_api_net_name=network_name, log_api_url="http://log_api:50005", log_container_name="log_api"))
        
        if "ssl" in service_version:
            services.append(NginxHoneypot(name=f"{name}_nginx", port=port, nginx_config=nginx_conf, token=self.token, nginx_api_net_name=network_name, api_container_name=f"{name}_api", create_cert="True", cn=cn, c=c, st=st, l=l, o=o, ou=ou))
        else:
            services.append(NginxHoneypot(name=f"{name}_nginx", port=port, nginx_config=nginx_conf, token=self.token, nginx_api_net_name=network_name, api_container_name=f"{name}_api", create_cert="False"))

        return services