from xscan.modules.graphql import graphql_detected, introspection_open


def test_introspection_open():
    assert introspection_open(200, '{"data":{"__schema":{"types":[{"name":"Query"}]}}}')


def test_introspection_closed():
    assert not introspection_open(200, '{"errors":[{"message":"Not authorised"}]}')


def test_graphql_get_error_message_detected():
    assert graphql_detected("GET query missing.")


def test_must_provide_query_detected():
    assert graphql_detected("Must provide query string.")


def test_random_response_not_graphql():
    assert not graphql_detected("<html>page classique</html>")
