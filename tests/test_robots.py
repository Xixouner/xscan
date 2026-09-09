from xscan.modules.robots import disallow_paths


def test_disallow_paths_extracted():
    robots = "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\nAllow: /public\n"
    assert disallow_paths(robots) == ["/admin", "/backup.zip"]


def test_disallow_root_and_wildcard_ignored():
    robots = "Disallow: /\nDisallow: *\nDisallow: /admin\n"
    assert disallow_paths(robots) == ["/admin"]


def test_deduplicated():
    robots = "Disallow: /a\nDisallow: /a\n"
    assert disallow_paths(robots) == ["/a"]


def test_empty_robots():
    assert disallow_paths("") == []
