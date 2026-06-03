"""
Covers the dockerizer's SSH hook: a normalized 'ssh' entry must turn into a
SshHoneypotService carrying the persona, with recon's captured banner folded in.

The logger is unused by _create_ssh_service, so we pass None and avoid a live log-api.
"""
import pytest

from dockerizer import Dockerizer
from services import SshHoneypotService


def _dockerizer():
    return Dockerizer(norm_data={}, output_path="/tmp", logger=None, token=None)


def test_create_ssh_service_builds_from_norm_data():
    data = {"port": 2222, "persona": {"hostname": "cam01"}}
    service = _dockerizer()._create_ssh_service(data=data, name="ssh_22")
    assert isinstance(service, SshHoneypotService)
    assert service.persona["hostname"] == "cam01"


def test_recon_banner_is_folded_into_persona():
    data = {"port": 22, "banner": "SSH-2.0-OpenSSH_7.4"}
    service = _dockerizer()._create_ssh_service(data=data, name="ssh_22")
    assert service.persona["banner"] == "SSH-2.0-OpenSSH_7.4"


def test_explicit_persona_banner_wins_over_recon_banner():
    data = {"port": 22, "banner": "SSH-2.0-OpenSSH_7.4",
            "persona": {"banner": "SSH-2.0-dropbear_2019.78"}}
    service = _dockerizer()._create_ssh_service(data=data, name="ssh_22")
    assert service.persona["banner"] == "SSH-2.0-dropbear_2019.78"


def test_missing_port_raises():
    with pytest.raises(ValueError):
        _dockerizer()._create_ssh_service(data={"persona": {}}, name="ssh_22")
