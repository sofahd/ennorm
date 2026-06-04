"""
Covers the normalizer's SSH gap: recon finds an SSH service on a port (empty endpoints,
nmap service name ``ssh``, an ``SSH-...`` banner) and EnNorm must emit an ``ssh_<port>``
entry the dockerizer routes to a SshHoneypotService -- instead of misfiling it as a generic
port_spoof.

The persona's ``banner`` must be recon's real captured banner so the spawned pot's
``nmap -sV`` fingerprint matches the cloned device.
"""
import json

import ennorm
from ennorm import EnNorm


class _StubLogger:
    """No-op stand-in for SofahLogger (EnNorm logs, but these tests don't assert on logs)."""

    def info(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


def _ennorm(tmp_path, ip="192.0.2.10"):
    return EnNorm(logger=_StubLogger(), token=None, ip=ip,
                  input_path=str(tmp_path), output_path=str(tmp_path))


# --------------------------------------------------------------------------- #
# detection
# --------------------------------------------------------------------------- #

def test_is_ssh_detects_nmap_service_name(tmp_path):
    # nmap -sV labels the SSH service "ssh" even when the banner grab returns nothing.
    assert _ennorm(tmp_path)._is_ssh({"service_version": "ssh", "banner": None})


def test_is_ssh_detects_banner_identification_string(tmp_path):
    # RFC 4253: an SSH server always opens with "SSH-<proto>-<software>".
    assert _ennorm(tmp_path)._is_ssh(
        {"service_version": None, "banner": "SSH-2.0-OpenSSH_7.4"}
    )


def test_is_ssh_rejects_non_ssh_port(tmp_path):
    assert not _ennorm(tmp_path)._is_ssh(
        {"service_version": "http", "banner": "Apache/2.4.7 (Ubuntu)"}
    )


# --------------------------------------------------------------------------- #
# emission
# --------------------------------------------------------------------------- #

def test_create_ssh_folds_recon_banner_into_persona(tmp_path):
    en = _ennorm(tmp_path)
    en._create_ssh(port_data={"banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"}, port="22")

    entry = en.container_structure["ssh_22"]
    assert entry["port"] == "22"
    assert entry["persona"]["banner"] == "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"


def test_create_ssh_without_banner_still_emits_entry(tmp_path):
    en = _ennorm(tmp_path)
    en._create_ssh(port_data={"banner": None}, port="2222")

    entry = en.container_structure["ssh_2222"]
    assert entry["port"] == "2222"
    assert entry["persona"] == {}  # nothing to clone -> the pot uses its own defaults


# --------------------------------------------------------------------------- #
# end-to-end routing: the actual gap being closed
# --------------------------------------------------------------------------- #

def test_process_routes_ssh_service_to_ssh_entry_not_portspoof(tmp_path, monkeypatch):
    ip = "192.0.2.10"
    # A realistic recon result for an open SSH port: no HTTP endpoints, nmap labelled it
    # "ssh", the banner script grabbed the identification string, port_spoof "mode" present.
    (tmp_path / f"{ip}.json").write_text(json.dumps({
        "22": {
            "endpoints": {},
            "protocol": "tcp",
            "timestamp": "1780301509",
            "mode": "banner",
            "service_version": "ssh",
            "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
        }
    }))

    captured = {}

    class _FakeDockerizer:
        # Intercept norm_data without writing docker-compose.yml or downloading repos.
        def __init__(self, norm_data, output_path, logger, token):
            captured["norm_data"] = norm_data

        def create_docker_compose(self):
            pass

    monkeypatch.setattr(ennorm, "Dockerizer", _FakeDockerizer)

    _ennorm(tmp_path, ip=ip).process()

    norm = captured["norm_data"]
    assert "ssh_22" in norm
    assert norm["ssh_22"]["port"] == "22"
    assert norm["ssh_22"]["persona"]["banner"] == "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    # the gap: an SSH service must not be misfiled as a generic port_spoof
    assert not any("poof" in key for key in norm)
