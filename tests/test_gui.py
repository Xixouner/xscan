import pytest

flet = pytest.importorskip("flet")


def test_gui_app_importable():
    from xscan.gui import app

    assert callable(app.main)
    assert hasattr(app, "XscanGui")
