from sofahutils import SofahLogger
import os, json
from urllib.parse import urlparse, parse_qs
from typing import Optional
from .dockerizer import Dockerizer


class EnNorm:
    """
    Class to enrich and normalize date for the SOFAH system.
    Here especially the data from the recon module is enriched and normalized. 
    """

    def __init__(self, logger:SofahLogger, token:str, ip:str, input_path:Optional[str] = "/home/ennorm/input", output_path:Optional[str] = "/home/ennorm/output", placeholder_vars:Optional[dict] = {}):
        """
        Constructor for the EnNorm class.

        The placeholder dict, contains values that are expected to be found in the data and should be replaced by the placeholder in the dict.
        Example:
        ```json
        {
            "127.0.0.1": "<local_ip>",
            "34JSD4": "<hostname>"
        }
        ```
        The placeholders will be again replaced when the data is served in the actual deployed honeypot.
        
        --- 
        :param logger: Logger object.
        :type logger: SofahLogger (from sofahutils)
        :param token: Github Token for generated containers
        :type token: str
        :param input_path: OPTIONAL (dont change this for use in docker) Path to the input directory. Default is "/home/ennorm/input".
        :type input_path: str
        :param ip: IP of the API.
        :type ip: str
        :param output_path: OPTIONAL (dont change this for use in docker) Path to the output directory. Default is "/home/ennorm/output".
        :type output_path: str
        :param placeholder_vars: OPTIONAL dict of placeholder variables. Default is {}.
        :type placeholder_vars: dict
        """

        self.logger = logger
        self.logger.info(message="EnNorm initialized", method="EnNorm.__init__")
        self.token = token
        self.ip = ip
        self.input_path = input_path
        self.output_path = output_path
        self.placeholder_vars = placeholder_vars
        self.container_structure = {}
    

    
    
    def process(self):
        """
        Enrich the data from the recon module.
        """

        recon_data = self._load_recon_data()

        regex_and_placeholder = self._create_regex_and_placeholder()

        self.logger.info(message="Enriching data from recon module", method="EnNorm._enrich_recon_data")

        for ip, port_dict in recon_data.items():
            
            for port in port_dict.keys():
                
                if port_dict[port]["endpoints"] != {}: # if there are endpoints, therefor this is an API!
                    self.logger.info(message=f"Creating API for {ip}:{port}", method="EnNorm._enrich_recon_data")
                    self._create_api(endpoints=port_dict[port]["endpoints"], ip=ip, port=port)

                else:
                    self.logger.info(message=f"Creating Port_spoof for {ip}:{port}", method="EnNorm._enrich_recon_data")
                    counter = 0
                    for key in self.container_structure.keys():
                        if "port_spoof" in key:
                            counter +=1
                    self.container_structure[f"poof{counter}"] = port_dict[port]
                    self.container_structure[f"poof{counter}"]["port"] = port
                    self.container_structure[f"poof{counter}"].pop("endpoints")
                    self.container_structure[f"poof{counter}"].pop("timestamp")



        self.container_structure["regex_and_placeholder"] = regex_and_placeholder

        self.logger.info(message="Enriching data from recon module finished", method="EnNorm._enrich_recon_data")
        
        dockerizer = Dockerizer(norm_data=self.container_structure, output_path=self.output_path, token=self.token, logger=self.logger)

        dockerizer.create_docker_compose()

                    
    def _load_recon_data(self) -> dict:
        """
        Load the data from the recon module.
        
        --- 
        :return: Data from the recon module.
        :rtype: dict
        """

        self.logger.info(message="Loading data from recon module", method="EnNorm._load_recon_data")
        file_list = self._create_list_of_files()

        recon_data = {}

        for file in file_list:
            if file.endswith(".json"):
                with open(os.path.join(self.input_path, file), "r") as f:
                    try:
                        recon_data[file.replace(".json", "")] = json.load(f)
                    except Exception as e:
                        self.logger.error(message=f"Error jsonifying data from {self.input_path + file}, {str(e)}", method="EnNorm._load_recon_data")
        
        return recon_data
    

    def _create_list_of_files(self) -> list[str]:
        """
        Create a list of files from the recon module.

        ---
        :return: List of files from the recon module.
        :rtype: list[str]
        """

        self.logger.info(message="Creating list of files from recon module", method="EnNorm._create_list_of_files")
        
        files_list = []

        for filename in os.listdir(self.input_path):
            if os.path.isfile(os.path.join(self.input_path, filename)) and self.ip in filename:
                files_list.append(filename)

        return files_list
    
    def _create_api(self, endpoints:dict, ip:str, port:str):
        """
        Create an API from the data of the recon module.

        ---
        :param endpoints: Endpoints of the API.
        :type endpoints: dict
        :param ip: IP of the API.
        :type ip: str
        :param port: Port of the API.
        :type port: str
        """

        self.logger.info(message=f"Creating API for {ip}:{port}", method="EnNorm._create_api")

        ret_dict = {}

        counter = 0
        for key in self.container_structure.keys():
            if "api" in key:
                counter +=1
        
        api_name = f"api_{counter}"

        self.container_structure[api_name] = {}
        
        for endpoint, data in endpoints.items():
            query_params = {}
            cleaned_endpoint = endpoint
            if "?" in endpoint:
                parsed_url = urlparse(endpoint)
                cleaned_endpoint = parsed_url.path
                query_params = parse_qs(parsed_url.query)
                
            ret_dict[cleaned_endpoint] = self._process_endpoint(endpoint_data=data, endpoint=cleaned_endpoint, api_name=api_name)
            ret_dict[cleaned_endpoint]["params"] = query_params
            
        # Here the Nginx config gets concatenated.
        nginx_config = []
        nginx_config.append(f"server {{")
        nginx_config.append(f"    listen {port};")
        nginx_config.append(f"    more_clear_headers 'Content-Disposition';")
        nginx_config.append(f"    more_clear_headers 'E-Tag';")
        for endpoint, data in ret_dict.items():
            nginx_config += data["nginx"]
            ret_dict[endpoint].pop("nginx") 
        nginx_config.append(f"}}")
        
        self.container_structure[api_name]["nginx"] = nginx_config
        self.container_structure[api_name]["endpoints"] = ret_dict
        self.container_structure[api_name]["port"] = port


    
    def _process_endpoint(self, endpoint_data:dict, endpoint:str, api_name:str) -> dict:
        """
        With this method an endpoint is created.
        Here the headers get cleaned, and the response data gets searched for values to be replaced by the placeholder.
        Also the nginx config is created.

        ---
        :param endpoint_data: Data of the endpoint.
        :type endpoint_data: dict
        :param endpoint: Name of the endpoint.
        :type endpoint: str
        :param api_name: Name of the API.
        :type api_name: str
        :return: Processed endpoint data.
        :rtype: dict
        """

        self.logger.info(message=f"Processing endpoint {endpoint}", method="EnNorm._process_endpoint")

        endpoint_data["headers"] = self._clean_headers(headers=endpoint_data["headers"])

        response_file_path = endpoint_data["path"]

        self._replace_values_with_placeholder(response_file_path=response_file_path)

        endpoint_data["nginx"] = self._create_nginx_config(endpoint=endpoint, endpoint_data=endpoint_data, api_name=api_name)

        return endpoint_data

    
    def _create_nginx_config(self, endpoint:str, endpoint_data:dict, api_name:str) -> list[str]:
        """
        This method will create the nginx config for **ONE** endpoint.
        Meaning, that the output of this method needs to be concatenated with the other nginx configs.

        ---
        :param endpoint: Name of the endpoint.
        :type endpoint: str
        :param endpoint_data: Data of the endpoint.
        :type endpoint_data: dict
        :param api_name: Name of the API.
        :type api_name: str
        :return: Nginx config for the endpoint.
        :rtype: list[str]
        """

        self.logger.info(message=f"Creating nginx config for {endpoint}", method="EnNorm._create_nginx_config")

        nginx_config = []
        

        if endpoint.endswith("/"):
            nginx_config.append(f"    location = \"{endpoint.replace('%20', ' ')}\" {{")
        else:
            nginx_config.append(f"    location \"{endpoint.replace('%20', ' ')}\" {{")
        nginx_config.append(f"        proxy_pass http://{api_name}_api:50005{endpoint};")
        
        for header, value in self._clean_headers(endpoint_data["headers"]).items():
            self.logger.info(message=f"Adding header {header} with value {value} to nginx config", method="EnNorm._create_nginx_config")
            nginx_config.append(f"        more_set_headers '{header}: {value}';")

        nginx_config.append(f"    }}")
        
        return nginx_config
    

    def _replace_values_with_placeholder(self, response_file_path:str):
        """
        This method will replace all values in the response file with the appropriate placeholder.

        ---
        :param response_file_path: Path to the response file.
        :type response_file_path: str
        """

        self.logger.info(message=f"Replacing values with placeholder in {response_file_path}", method="EnNorm._replace_values_with_placeholder")
        try:
            with open(response_file_path, "r") as f:
                lines = f.readlines()
            
            cleaned_lines = []

            for line in lines:
                for value, placeholder in self.placeholder_vars.items():
                    line = line.replace(value, placeholder)
                cleaned_lines.append(line)
        
            with open(response_file_path, "w") as f:
                f.writelines(cleaned_lines)
        except Exception as e:
            self.logger.error(message=f"Error replacing values with placeholder in {response_file_path}, {str(e)}", method="EnNorm._replace_values_with_placeholder")

    def _clean_headers(self, headers:dict) -> dict:
        """
        Clean the headers of the API.

        ---
        :param headers: Headers of the API.
        :type headers: dict
        :return: Cleaned headers of the API.
        :rtype: dict
        """

        self.logger.info(message="Cleaning headers", method="EnNorm._clean_headers")

        cleaned_headers = {}

        for key, value in headers.items():
            if key.lower() not in ["date", "etag", "connection", "transfer-encoding", "content-encoding"]:
                cleaned_headers[key] = value

        return cleaned_headers


    def _create_regex_and_placeholder(self) -> dict:
        """
        This method is designed to create a dict of placeholder and the appropriate regex for the placeholder.
        The keys of the dict are the placeholders and the values are the regex.
        
        ---
        :return: Dict of placeholder and regex.
        :rtype: dict
        """

        self.logger.info(message="Creating regex and placeholder", method="EnNorm._create_regex_and_placeholder")

        placeholder_and_regex = {}

        for value, placeholder in self.placeholder_vars.items():
            placeholder_and_regex[placeholder] = self._create_regex_from_string(value)

        return placeholder_and_regex


    def _create_regex_from_string(self, create_from:str) -> str:
        """
        This function is designed to take a string and create regex with similar semantic.
        For example, from the Hostname string "H9JSD4-af3" it will create the regex "[A-Z][0-9][A-Z][A-Z][A-Z][0-9]-[a-z][a-z][0-9]".

        ---
        :param create_from: String to create regex from.
        :type create_from: str
        :return: Regex created from the string.
        """
        
        self.logger.info(message=f"Creating regex from {create_from}", method="EnNorm._create_regex_from_string")

        regex = ""
        for char in create_from:
            regex += self._get_regex_for_char(char)
        
        return regex



    def _get_regex_for_char(self, char:str) -> str:
        """
        Get the regex for a single character.
        
        ---
        :param char: Character for which the regex is needed.
        :type char: str
        :return: Regex for the character.
        """
        
        if char.isalpha():
            if char.islower():
                return "[a-z]"
            else:
                return "[A-Z]"
        elif char.isdigit():
            return "[0-9]"
        else:
            return char


