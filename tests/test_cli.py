from typer.testing import CliRunner

from xscan.cli import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "xscan" in result.output


def test_unknown_module_rejected():
    result = runner.invoke(app, ["scan", "https://cible.test", "--modules", "moduleinvente"])
    assert result.exit_code != 0
    assert "modules inconnus" in result.output


def test_invalid_url_rejected():
    result = runner.invoke(app, ["scan", "ftp://cible.test"])
    assert result.exit_code != 0
    assert "URL invalide" in result.output
