from xscan.modules.sourcemaps import is_sourcemap, map_url_for

MAP_BODY = '{"version":3,"sources":["webpack:///chunk.js"],"mappings":"AAAA"}'


def test_map_url():
    assert map_url_for("https://t.test/_next/static/chunk.js") == "https://t.test/_next/static/chunk.js.map"


def test_real_sourcemap_detected():
    assert is_sourcemap(200, MAP_BODY)


def test_spa_404_not_flagged():
    html = "<!DOCTYPE html><html><body>404 page</body></html>"
    assert not is_sourcemap(200, html)


def test_json_without_mappings_not_flagged():
    assert not is_sourcemap(200, '{"message": "not found"}')


def test_error_status_not_flagged():
    assert not is_sourcemap(404, MAP_BODY)
