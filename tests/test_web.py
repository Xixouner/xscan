import pytest

from xscan.web import normalize_target


def test_normalize_adds_https():
    assert normalize_target("xixouner.com") == "https://xixouner.com"


def test_normalize_keeps_existing_scheme():
    assert normalize_target("http://t.test") == "http://t.test"
    assert normalize_target("https://t.test/") == "https://t.test/"


def test_normalize_rejects_ftp():
    with pytest.raises(ValueError):
        normalize_target("ftp://t.test")


def test_normalize_rejects_empty_host():
    with pytest.raises(ValueError):
        normalize_target("https://")
