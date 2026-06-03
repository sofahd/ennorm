import os
import sys

# Make the ennorm source tree importable (cert_forge, ennorm, dockerizer) without installing it.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
# In the multi-repo dev checkout sofahutils/services are sibling repos; in CI they are pip-installed.
for _sibling in ("sofahutils", "services"):
    _path = os.path.join(os.path.dirname(__file__), "..", "..", _sibling)
    if os.path.isdir(_path):
        sys.path.insert(0, _path)
