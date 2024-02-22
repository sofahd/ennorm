from ennorm import EnNorm
from sofahutils import SofahLogger
import os, json

token = os.getenv("TOKEN")
log_api = os.getenv("LOG_API")
ip = os.getenv("IP")

with open("/home/pro/data/conf/vars.json", "r") as f:
    variables_to_replace = json.load(f)

logger = SofahLogger(url=log_api)
ennorm = EnNorm(placeholder_vars=variables_to_replace, logger=logger, token=token , ip=ip)
ennorm.process()

