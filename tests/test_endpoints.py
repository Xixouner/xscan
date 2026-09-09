from xscan.modules import endpoints


def test_extract_paths_from_js():
    js = 'fetch("/api/v1/users"); const x = "/admin/debug"; let u = "https://cdn.t/lib.js"; const q = "/x"'
    paths = endpoints._extract_paths(js)
    assert {"/api/v1/users", "/admin/debug", "/x"} <= paths
    assert "https://cdn.t/lib.js" not in paths


def test_extract_paths_dedupes():
    js = 'fetch("/api/a"); fetch("/api/a");'
    assert endpoints._extract_paths(js) == {"/api/a"}


def test_interesting_paths_classified():
    assert endpoints._INTERESTING.search("/api/v1/users")
    assert endpoints._INTERESTING.search("/admin/debug")
    assert not endpoints._INTERESTING.search("/static/logo")
