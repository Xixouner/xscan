from xscan.setup_nuclei import asset_needle, pick_asset


def test_asset_needle():
    assert asset_needle("Linux", "x86_64") == "linux_amd64.zip"
    assert asset_needle("Linux", "aarch64") == "linux_arm64.zip"
    assert asset_needle("Darwin", "arm64") == "darwin_arm64.zip"
    assert asset_needle("Windows", "x86_64") is None
    assert asset_needle("Linux", "sparc64") is None


def test_pick_asset_matches_and_skips_checksums():
    assets = [
        {"name": "nuclei_3.3.9_checksums.txt", "browser_download_url": "https://x/checksums.txt"},
        {"name": "nuclei_3.3.9_linux_amd64.zip", "browser_download_url": "https://x/linux_amd64.zip"},
        {"name": "nuclei_3.3.9_darwin_arm64.zip", "browser_download_url": "https://x/darwin_arm64.zip"},
    ]
    assert pick_asset(assets, "linux_amd64.zip") == "https://x/linux_amd64.zip"
    assert pick_asset(assets, "linux_arm64.zip") is None


def test_pick_asset_empty():
    assert pick_asset([], "linux_amd64.zip") is None
