from xscan.modules.ports import _CHECKS
from xscan.models import Severity


def test_sensitive_services_configured():
    by_port = {port: severity for port, _, severity in _CHECKS}
    assert by_port[6379] is Severity.HIGH  # Redis sans auth = classique
    assert by_port[27017] is Severity.CRITICAL  # MongoDB exposé = breach
    assert by_port[5432] is Severity.MEDIUM  # PostgreSQL


def test_common_web_ports_not_probed():
    # 80/443 : derrière un CDN ils seraient de faux positifs — on ne les sonde pas
    by_port = {port for port, _, _ in _CHECKS}
    assert 80 not in by_port and 443 not in by_port
