# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import pytest

from keystone_role_assignment_openfga import plugin
from keystone_role_assignment_openfga import config as plugin_config
from keystone.common import provider_api
from keystone import exception

from requests import HTTPError
import requests_mock
from oslo_config import cfg

PROVIDERS = provider_api.ProviderAPIs
ROLES = [
    {"id": "reader_role_id", "name": "reader"},
    {"id": "manager_role_id", "name": "manager"},
]
ROLES_BY_NAME: dict[str, str] = {x["name"]: x["id"] for x in ROLES}
ROLES_BY_ID: dict[str, str] = {x["id"]: x["name"] for x in ROLES}


class RoleApiMock:
    def list_roles(*args, **kwargs):
        return ROLES


PROVIDERS._register_provider_api("role_api", RoleApiMock)


@pytest.fixture
def config():
    plugin_config.register_opts(cfg.CONF)
    cfg.CONF.set_override("api_url", "http://localhost:8080", group="fga")
    cfg.CONF.set_override("store_id", "foo", group="fga")
    cfg.CONF.set_override("model_id", "bar", group="fga")
    cfg.CONF.set_override("verify", False, group="fga")
    return cfg


def test_convert_openfga_to_assignment_base_up():
    assert plugin.convert_openfga_tuple_to_assignment_base(
        "user:foo", "project:bar"
    ) == {"user_id": "foo", "project_id": "bar"}


def test_convert_openfga_to_assignment_base_ud():
    assert plugin.convert_openfga_tuple_to_assignment_base(
        "user:foo", "domain:bar"
    ) == {"user_id": "foo", "domain_id": "bar"}


def test_convert_openfga_to_assignment_base_us():
    assert plugin.convert_openfga_tuple_to_assignment_base(
        "user:foo", "system:all"
    ) == {"user_id": "foo", "system_id": "all"}


def test_convert_openfga_to_assignment_base_gp():
    assert plugin.convert_openfga_tuple_to_assignment_base(
        "group:foo", "project:bar"
    ) == {"group_id": "foo", "project_id": "bar"}


def test_convert_openfga_to_assignment_base_gd():
    assert plugin.convert_openfga_tuple_to_assignment_base(
        "group:foo", "domain:bar"
    ) == {"group_id": "foo", "domain_id": "bar"}


def test_convert_openfga_to_assignment_base_gs():
    assert plugin.convert_openfga_tuple_to_assignment_base(
        "group:foo", "system:all"
    ) == {"group_id": "foo", "system_id": "all"}


def test_convert_openfga_tuple_to_assignment_gs():
    assert plugin.convert_openfga_tuple_to_assignment(
        {"user": "group:foo", "object": "project:bar", "relation": "reader"},
        ROLES_BY_NAME,
    ) == {"group_id": "foo", "project_id": "bar", "role_id": "reader_role_id"}


def test_convert_assignment_to_openfga_tuple():
    assert plugin.convert_assignment_to_openfga_tuple(
        "reader", user_id="foo", project_id="bar"
    ) == {"user": "user:foo", "object": "project:bar", "relation": "reader"}
    assert plugin.convert_assignment_to_openfga_tuple(
        "reader", group_id="foo", project_id="bar"
    ) == {"user": "group:foo", "object": "project:bar", "relation": "reader"}
    assert plugin.convert_assignment_to_openfga_tuple(
        "reader", user_id="foo", domain_id="bar"
    ) == {"user": "user:foo", "object": "domain:bar", "relation": "reader"}
    assert plugin.convert_assignment_to_openfga_tuple(
        "reader", group_id="foo", domain_id="bar"
    ) == {"user": "group:foo", "object": "domain:bar", "relation": "reader"}
    assert plugin.convert_assignment_to_openfga_tuple(
        "reader", user_id="foo", system_id="bar"
    ) == {"user": "user:foo", "object": "system:bar", "relation": "reader"}
    assert plugin.convert_assignment_to_openfga_tuple(
        "reader", group_id="foo", system_id="bar"
    ) == {"user": "group:foo", "object": "system:bar", "relation": "reader"}

    with pytest.raises(RuntimeError):
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", user_id="foo", group_id="bar"
        )
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", project_id="foo", domain_id="bar"
        )
        assert plugin.convert_assignment_to_openfga_tuple("reader")


def test_plugin_init(requests_mock, config):
    driver = plugin.OpenFGA()
    assert driver.conf.fga.api_url == "http://localhost:8080"
    assert driver.conf.fga.store_id == "foo"
    assert driver.conf.fga.model_id == "bar"
    assert driver.conf.fga.verify == False


def test_list_role_assignments_500(requests_mock, config):
    driver = plugin.OpenFGA()
    requests_mock.post(
        "http://localhost:8080/stores/foo/read", status_code=500
    )
    res = driver.list_role_assignments()
    assert res == []


def test_list_role_assignments_non_json(requests_mock, config):
    driver = plugin.OpenFGA()
    requests_mock.post(
        "http://localhost:8080/stores/foo/read", text="dummy response"
    )
    res = driver.list_role_assignments()
    assert res == []


def test_list_role_assignments_202(requests_mock, config):
    driver = plugin.OpenFGA()
    requests_mock.post(
        "http://localhost:8080/stores/foo/read", status_code=202, json={}
    )
    res = driver.list_role_assignments()
    assert res == []


def test_list_role_assignments(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        json={
            "tuples": [
                {
                    "key": {
                        "user": "user:bob",
                        "relation": "reader",
                        "object": "project:foo",
                    }
                },
                {
                    "key": {
                        "user": "user:bob",
                        "relation": "manager",
                        "object": "domain:bar",
                    }
                },
                {
                    "key": {
                        "user": "user:alice",
                        "relation": "supervisor",
                        "object": "domain:bar",
                    }
                },
            ]
        },
    )
    res = driver.list_role_assignments()
    assert res == [
        {"project_id": "foo", "role_id": "reader_role_id", "user_id": "bob"},
        {"domain_id": "bar", "role_id": "manager_role_id", "user_id": "bob"},
    ]


def test_list_role_assignments_bad_response(
    monkeypatch, requests_mock, config
):
    driver = plugin.OpenFGA()

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        json={
            "tuples1": [
                {
                    "key": {
                        "user": "user:bob",
                        "relation": "reader",
                        "object": "project:foo",
                    }
                }
            ]
        },
    )
    res = driver.list_role_assignments()
    assert res == []

    requests_mock.post(
        "http://localhost:8080/stores/foo/read", json={"tuples": "foo"}
    )
    res = driver.list_role_assignments()
    assert res == []


def test_add_role_to_user_and_project(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_request(request):
        return {
            "writes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "user:foo",
                        "object": "project:bar",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_request,
    )
    driver.add_role_to_user_and_project("foo", "bar", "reader_role_id")


def test_add_role_to_user_and_project_409(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write", status_code=409
    )
    with pytest.raises(exception.Conflict):
        driver.add_role_to_user_and_project("foo", "bar", "reader_role_id")


def test_remove_role_from_user_and_project(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_request(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "user:foo",
                        "object": "project:bar",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_request,
    )
    driver.remove_role_from_user_and_project("foo", "bar", "reader_role_id")


def test_create_grant(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_user_request(request):
        return {
            "writes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "user:foo",
                        "object": "project:bar",
                    }
                ]
            }
        } == request.json()

    def match_group_request(request):
        return {
            "writes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "group:foo",
                        "object": "project:bar",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_user_request,
    )
    driver.create_grant("reader_role_id", user_id="foo", project_id="bar")

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_group_request,
    )
    driver.create_grant("reader_role_id", group_id="foo", project_id="bar")


def test_delete_grant(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_user_request(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "user:foo",
                        "object": "project:bar",
                    }
                ]
            }
        } == request.json()

    def match_group_request(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "group:foo",
                        "object": "project:bar",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_user_request,
    )
    driver.delete_grant("reader_role_id", user_id="foo", project_id="bar")

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_group_request,
    )
    driver.delete_grant("reader_role_id", group_id="foo", project_id="bar")


def test_create_system_grant(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_user_system_request(request):
        return {
            "writes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "user:foo",
                        "object": "system:bar",
                    }
                ]
            }
        } == request.json()

    def match_group_system_request(request):
        return {
            "writes": {
                "tuple_keys": [
                    {
                        "relation": "reader",
                        "user": "group:foo",
                        "object": "system:bar",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_user_system_request,
    )
    driver.create_system_grant(
        "reader_role_id", "foo", "bar", "UserSystem", False
    )
    driver.create_system_grant(
        "reader_role_id", "foo", "bar", "UserSystem", True
    )

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_group_system_request,
    )
    driver.create_system_grant(
        "reader_role_id", "foo", "bar", "GroupSystem", False
    )
    driver.create_system_grant(
        "reader_role_id", "foo", "bar", "GroupSystem", True
    )
