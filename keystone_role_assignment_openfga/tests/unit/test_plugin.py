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


import logging
import pytest
from keystone import exception
from keystone.common import provider_api
from oslo_config import cfg

from keystone_role_assignment_openfga import config as plugin_config
from keystone_role_assignment_openfga import plugin

LOG = logging.getLogger(__name__)

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


class TestConvert:
    def test_convert_openfga_to_assignment_base_up(self):
        assert plugin.convert_openfga_tuple_to_assignment_base(
            "user:foo", "project:bar"
        ) == {"type": "UserProject", "actor_id": "foo", "target_id": "bar"}

    def test_convert_openfga_to_assignment_base_ud(self):
        assert plugin.convert_openfga_tuple_to_assignment_base(
            "user:foo", "domain:bar"
        ) == {"type": "UserDomain", "actor_id": "foo", "target_id": "bar"}

    def test_convert_openfga_to_assignment_base_us(self):
        assert plugin.convert_openfga_tuple_to_assignment_base(
            "user:foo", "system:all"
        ) == {"type": "UserSystem", "actor_id": "foo", "target_id": "all"}

    def test_convert_openfga_to_assignment_base_gp(self):
        assert plugin.convert_openfga_tuple_to_assignment_base(
            "group:foo", "project:bar"
        ) == {"type": "GroupProject", "actor_id": "foo", "target_id": "bar"}

    def test_convert_openfga_to_assignment_base_gd(self):
        assert plugin.convert_openfga_tuple_to_assignment_base(
            "group:foo", "domain:bar"
        ) == {"type": "GroupDomain", "actor_id": "foo", "target_id": "bar"}

    def test_convert_openfga_to_assignment_base_gs(self):
        assert plugin.convert_openfga_tuple_to_assignment_base(
            "group:foo", "system:all"
        ) == {"type": "GroupSystem", "actor_id": "foo", "target_id": "all"}

    def test_convert_openfga_tuple_to_assignment_gs(self):
        assert plugin.convert_openfga_tuple_to_assignment(
            {
                "user": "group:foo",
                "object": "project:bar",
                "relation": "reader",
            },
            ROLES_BY_NAME,
        ) == {
            "role_id": "reader_role_id",
            "type": "GroupProject",
            "actor_id": "foo",
            "target_id": "bar",
        }

    def test_denormalize_assignment_up(self):
        assert plugin.denormalize_assignment({
            "type": "UserProject",
            "actor_id": "foo",
            "target_id": "bar",
        }) == {
            "user_id": "foo",
            "project_id": "bar",
            "type": "UserProject",
            "actor_id": "foo",
            "target_id": "bar",
        }

    def test_denormalize_assignment_ud(self):
        assert plugin.denormalize_assignment({
            "type": "UserDomain",
            "actor_id": "foo",
            "target_id": "bar",
        }) == {
            "user_id": "foo",
            "domain_id": "bar",
            "type": "UserDomain",
            "actor_id": "foo",
            "target_id": "bar",
        }

    def test_denormalize_assignment_us(self):
        assert plugin.denormalize_assignment({
            "type": "UserSystem",
            "actor_id": "foo",
            "target_id": "all",
        }) == {
            "user_id": "foo",
            "system_id": "all",
            "type": "UserSystem",
            "actor_id": "foo",
            "target_id": "all",
        }

    def test_denormalize_assignment_gp(self):
        assert plugin.denormalize_assignment({
            "type": "GroupProject",
            "actor_id": "foo",
            "target_id": "bar",
        }) == {
            "group_id": "foo",
            "project_id": "bar",
            "type": "GroupProject",
            "actor_id": "foo",
            "target_id": "bar",
        }

    def test_denormalize_assignment_gd(self):
        assert plugin.denormalize_assignment({
            "type": "GroupDomain",
            "actor_id": "foo",
            "target_id": "bar",
        }) == {
            "group_id": "foo",
            "domain_id": "bar",
            "type": "GroupDomain",
            "actor_id": "foo",
            "target_id": "bar",
        }

    def test_denormalize_assignment_gs(self):
        assert plugin.denormalize_assignment({
            "type": "GroupSystem",
            "actor_id": "foo",
            "target_id": "all",
        }) == {
            "group_id": "foo",
            "system_id": "all",
            "type": "GroupSystem",
            "actor_id": "foo",
            "target_id": "all",
        }

    def test_convert_assignment_to_openfga_tuple(self):
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", user_id="foo", project_id="bar"
        ) == {
            "user": "user:foo",
            "object": "project:bar",
            "relation": "reader",
        }
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", group_id="foo", project_id="bar"
        ) == {
            "user": "group:foo",
            "object": "project:bar",
            "relation": "reader",
        }
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", user_id="foo", domain_id="bar"
        ) == {"user": "user:foo", "object": "domain:bar", "relation": "reader"}
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", group_id="foo", domain_id="bar"
        ) == {
            "user": "group:foo",
            "object": "domain:bar",
            "relation": "reader",
        }
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", user_id="foo", system_id="bar"
        ) == {"user": "user:foo", "object": "system:bar", "relation": "reader"}
        assert plugin.convert_assignment_to_openfga_tuple(
            "reader", group_id="foo", system_id="bar"
        ) == {
            "user": "group:foo",
            "object": "system:bar",
            "relation": "reader",
        }

        with pytest.raises(RuntimeError):
            assert plugin.convert_assignment_to_openfga_tuple(
                "reader", user_id="foo", group_id="bar"
            )
            assert plugin.convert_assignment_to_openfga_tuple(
                "reader", project_id="foo", domain_id="bar"
            )
            assert plugin.convert_assignment_to_openfga_tuple("reader")


class TestReadTuples:
    def test_openfga_read_assignments_filter_unknown_relation(
        self, requests_mock, config
    ):
        driver = plugin.OpenFGA()

        def match_project_request(request):
            return {
                "tuple_key": {"user": "foo", "object": "project:"}
            } == request.json()

        def match_domain_request(request):
            return {
                "tuple_key": {"user": "foo", "object": "domain:"}
            } == request.json()

        mock_project = requests_mock.post(
            "http://localhost:8080/stores/foo/read",
            additional_matcher=match_project_request,
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
                            "relation": "unsupported",
                            "object": "project:bar",
                        }
                    },
                ]
            },
        )
        mock_domain = requests_mock.post(
            "http://localhost:8080/stores/foo/read",
            additional_matcher=match_domain_request,
            json={
                "tuples": [
                    {
                        "key": {
                            "user": "user:bob",
                            "relation": "manager",
                            "object": "domain:bar",
                        }
                    },
                    {
                        "key": {
                            "user": "user:bob",
                            "relation": "unsupported",
                            "object": "domain:bar",
                        }
                    },
                ]
            },
        )

        assignments = list(driver.openfga_read_assignments({"user": "foo"}))
        assert mock_project.called
        assert mock_domain.called
        assert [
            {
                "actor_id": "bob",
                "role_id": "reader_role_id",
                "target_id": "foo",
                "type": "UserProject",
            },
            {
                "actor_id": "bob",
                "role_id": "manager_role_id",
                "target_id": "bar",
                "type": "UserDomain",
            },
        ] == assignments

    def test_openfga_read_assignments_user_only(self, requests_mock, config):
        driver = plugin.OpenFGA()

        def match_project_request(request):
            return {
                "tuple_key": {"user": "foo", "object": "project:"}
            } == request.json()

        def match_domain_request(request):
            return {
                "tuple_key": {"user": "foo", "object": "domain:"}
            } == request.json()

        mock_project = requests_mock.post(
            "http://localhost:8080/stores/foo/read",
            additional_matcher=match_project_request,
            json={
                "tuples": [
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
        mock_domain = requests_mock.post(
            "http://localhost:8080/stores/foo/read",
            additional_matcher=match_domain_request,
            json={
                "tuples": [
                    {
                        "key": {
                            "user": "user:bob",
                            "relation": "manager",
                            "object": "domain:bar",
                        }
                    }
                ]
            },
        )

        assignments = list(driver.openfga_read_assignments({"user": "foo"}))
        assert mock_project.called
        assert mock_domain.called
        assert [
            {
                "actor_id": "bob",
                "role_id": "reader_role_id",
                "target_id": "foo",
                "type": "UserProject",
            },
            {
                "actor_id": "bob",
                "role_id": "manager_role_id",
                "target_id": "bar",
                "type": "UserDomain",
            },
        ] == assignments

    def test_openfga_read_assignments_user_and_relation(
        self, requests_mock, config
    ):
        driver = plugin.OpenFGA()

        def match_project_request(request):
            return {
                "tuple_key": {
                    "user": "foo",
                    "relation": "reader",
                    "object": "project:",
                }
            } == request.json()

        def match_domain_request(request):
            return {
                "tuple_key": {
                    "user": "foo",
                    "relation": "reader",
                    "object": "domain:",
                }
            } == request.json()

        mock_project = requests_mock.post(
            "http://localhost:8080/stores/foo/read",
            additional_matcher=match_project_request,
            json={
                "tuples": [
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
        mock_domain = requests_mock.post(
            "http://localhost:8080/stores/foo/read",
            additional_matcher=match_domain_request,
            json={
                "tuples": [
                    {
                        "key": {
                            "user": "user:bob",
                            "relation": "reader",
                            "object": "domain:bar",
                        }
                    }
                ]
            },
        )

        assignments = list(
            driver.openfga_read_assignments({
                "user": "foo",
                "relation": "reader",
            })
        )
        assert mock_project.called
        assert mock_domain.called
        assert [
            {
                "actor_id": "bob",
                "role_id": "reader_role_id",
                "target_id": "foo",
                "type": "UserProject",
            },
            {
                "actor_id": "bob",
                "role_id": "reader_role_id",
                "target_id": "bar",
                "type": "UserDomain",
            },
        ] == assignments

    def test_openfga_read_assignments_user_object(self, requests_mock, config):
        driver = plugin.OpenFGA()

        def match_request(request):
            return {
                "tuple_key": {"user": "user:bob", "object": "project:foo"}
            } == request.json()

        mock = requests_mock.post(
            "http://localhost:8080/stores/foo/read",
            additional_matcher=match_request,
            json={
                "tuples": [
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

        assignments = list(
            driver.openfga_read_assignments({
                "user": "user:bob",
                "object": "project:foo",
            })
        )
        assert mock.called
        assert [
            {
                "actor_id": "bob",
                "role_id": "reader_role_id",
                "target_id": "foo",
                "type": "UserProject",
            }
        ] == assignments


def test_plugin_init(config):
    driver = plugin.OpenFGA()
    assert driver.conf.fga.api_url == "http://localhost:8080"
    assert driver.conf.fga.store_id == "foo"
    assert driver.conf.fga.model_id == "bar"
    assert not driver.conf.fga.verify


class TestListAssignments:
    def test_list_role_assignments_500(self, requests_mock, config):
        driver = plugin.OpenFGA()
        requests_mock.post(
            "http://localhost:8080/stores/foo/read", status_code=500
        )
        res = driver.list_role_assignments()
        assert res == []

    def test_list_role_assignments_non_json(self, requests_mock, config):
        driver = plugin.OpenFGA()
        requests_mock.post(
            "http://localhost:8080/stores/foo/read", text="dummy response"
        )
        res = driver.list_role_assignments()
        assert res == []

    def test_list_role_assignments_202(self, requests_mock, config):
        driver = plugin.OpenFGA()
        requests_mock.post(
            "http://localhost:8080/stores/foo/read", status_code=202, json={}
        )
        res = driver.list_role_assignments()
        assert res == []

    def test_list_role_assignments(self, monkeypatch, requests_mock, config):
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
            {
                "project_id": "foo",
                "role_id": "reader_role_id",
                "user_id": "bob",
                "type": "UserProject",
                "actor_id": "bob",
                "target_id": "foo",
            },
            {
                "domain_id": "bar",
                "role_id": "manager_role_id",
                "user_id": "bob",
                "type": "UserDomain",
                "actor_id": "bob",
                "target_id": "bar",
            },
        ]

    def test_list_role_assignments_actor_target(
        self, monkeypatch, requests_mock, config
    ):
        driver = plugin.OpenFGA()

        def match_batch_request(request):
            return {
                "checks": [
                    {
                        "tuple_key": {
                            "object": "project:bar",
                            "relation": "reader",
                            "user": "user:foo",
                        },
                        "correlation_id": "reader_role_id",
                    },
                    {
                        "tuple_key": {
                            "object": "project:bar",
                            "relation": "manager",
                            "user": "user:foo",
                        },
                        "correlation_id": "manager_role_id",
                    },
                ]
            } == request.json()

        requests_mock.post(
            "http://localhost:8080/stores/foo/batch-check",
            additional_matcher=match_batch_request,
            json={
                "result": {
                    "reader_role_id": {"allowed": True},
                    "manager_role_id": {"allowed": False},
                }
            },
        )

        res = driver.list_role_assignments(user_id="foo", project_ids=["bar"])
        assert res == [
            {
                "project_id": "bar",
                "role_id": "reader_role_id",
                "user_id": "foo",
                "type": "UserProject",
                "actor_id": "foo",
                "target_id": "bar",
            }
        ]

        requests_mock.post(
            "http://localhost:8080/stores/foo/batch-check",
            additional_matcher=match_batch_request,
            json={
                "result": {
                    "reader_role_id": {"allowed": True},
                    "manager_role_id": {"allowed": True},
                }
            },
        )

        res = driver.list_role_assignments(user_id="foo", project_ids=["bar"])
        assert res == [
            {
                "project_id": "bar",
                "role_id": "reader_role_id",
                "user_id": "foo",
                "type": "UserProject",
                "actor_id": "foo",
                "target_id": "bar",
            },
            {
                "project_id": "bar",
                "role_id": "manager_role_id",
                "user_id": "foo",
                "type": "UserProject",
                "actor_id": "foo",
                "target_id": "bar",
            },
        ]

    def test_list_role_assignments_bad_response(
        self, monkeypatch, requests_mock, config
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


def test_delete_project_assignments(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_query(request):
        return {"tuple_key": {"object": "project:foo"}} == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query,
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
                        "user": "user:tom",
                        "relation": "manager",
                        "object": "project:foo",
                    }
                },
                {
                    "key": {
                        "user": "user:alice",
                        "relation": "supervisor",
                        "object": "project:foo",
                    }
                },
            ]
        },
    )

    def match_change(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "user": "user:bob",
                        "relation": "reader",
                        "object": "project:foo",
                    },
                    {
                        "user": "user:tom",
                        "relation": "manager",
                        "object": "project:foo",
                    },
                    {
                        "user": "user:alice",
                        "relation": "supervisor",
                        "object": "project:foo",
                    },
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_change,
    )
    driver.delete_project_assignments("foo")


def test_delete_domain_assignments(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_query(request):
        return {"tuple_key": {"object": "domain:foo"}} == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query,
        json={
            "tuples": [
                {
                    "key": {
                        "user": "user:bob",
                        "relation": "reader",
                        "object": "domain:foo",
                    }
                },
                {
                    "key": {
                        "user": "user:tom",
                        "relation": "manager",
                        "object": "domain:foo",
                    }
                },
                {
                    "key": {
                        "user": "user:alice",
                        "relation": "supervisor",
                        "object": "domain:foo",
                    }
                },
            ]
        },
    )

    def match_change(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "user": "user:bob",
                        "relation": "reader",
                        "object": "domain:foo",
                    },
                    {
                        "user": "user:tom",
                        "relation": "manager",
                        "object": "domain:foo",
                    },
                    {
                        "user": "user:alice",
                        "relation": "supervisor",
                        "object": "domain:foo",
                    },
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_change,
    )
    driver.delete_domain_assignments("foo")


def test_delete_user_assignments(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_query_project(request):
        return {
            "tuple_key": {"user": "user:foo", "object": "project:"}
        } == request.json()

    def match_query_domain(request):
        return {
            "tuple_key": {"user": "user:foo", "object": "domain:"}
        } == request.json()

    def match_query_system(request):
        return {
            "tuple_key": {"user": "user:foo", "object": "system:"}
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query_project,
        json={
            "tuples": [
                {
                    "key": {
                        "user": "user:foo",
                        "relation": "reader",
                        "object": "project:bar",
                    }
                },
                {
                    "key": {
                        "user": "user:foo",
                        "relation": "manager",
                        "object": "project:baz",
                    }
                },
            ]
        },
    )
    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query_domain,
        json={
            "tuples": [
                {
                    "key": {
                        "user": "user:foo",
                        "relation": "reader",
                        "object": "domain:bar",
                    }
                }
            ]
        },
    )

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query_system,
        json={"tuples": []},
    )

    def match_change_project(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "user": "user:foo",
                        "relation": "reader",
                        "object": "project:bar",
                    },
                    {
                        "user": "user:foo",
                        "relation": "manager",
                        "object": "project:baz",
                    },
                ]
            }
        } == request.json()

    def match_change_domain(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "user": "user:foo",
                        "relation": "reader",
                        "object": "domain:bar",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_change_project,
    )
    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_change_domain,
    )
    driver.delete_user_assignments("foo")


def test_delete_group_assignments(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_query_project(request):
        return {
            "tuple_key": {"user": "group:foo", "object": "project:"}
        } == request.json()

    def match_query_domain(request):
        return {
            "tuple_key": {"user": "group:foo", "object": "domain:"}
        } == request.json()

    def match_query_system(request):
        return {
            "tuple_key": {"user": "group:foo", "object": "system:"}
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query_project,
        json={
            "tuples": [
                {
                    "key": {
                        "user": "group:foo",
                        "relation": "reader",
                        "object": "project:bar",
                    }
                },
                {
                    "key": {
                        "user": "group:foo",
                        "relation": "manager",
                        "object": "project:baz",
                    }
                },
            ]
        },
    )
    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query_domain,
        json={
            "tuples": [
                {
                    "key": {
                        "user": "group:foo",
                        "relation": "reader",
                        "object": "domain:bar",
                    }
                }
            ]
        },
    )

    requests_mock.post(
        "http://localhost:8080/stores/foo/read",
        additional_matcher=match_query_system,
        json={"tuples": []},
    )

    def match_change_project(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "user": "group:foo",
                        "relation": "reader",
                        "object": "project:bar",
                    },
                    {
                        "user": "group:foo",
                        "relation": "manager",
                        "object": "project:baz",
                    },
                ]
            }
        } == request.json()

    def match_change_domain(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "user": "group:foo",
                        "relation": "reader",
                        "object": "domain:bar",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_change_project,
    )
    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_change_domain,
    )
    driver.delete_group_assignments("foo")


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


def test_check_system_grant(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_batch_request(request):
        return {
            "checks": [
                {
                    "tuple_key": {
                        "object": "system:bar",
                        "relation": "reader",
                        "user": "user:foo",
                    }
                },
                {
                    "tuple_key": {
                        "object": "system:bar",
                        "relation": "reader",
                        "user": "group:foo",
                    }
                },
            ]
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/batch-check",
        additional_matcher=match_batch_request,
        json={"result": {"d1": {"allowed": False}, "d2": {"allowed": True}}},
    )
    assert driver.check_system_grant("reader_role_id", "foo", "bar", False)

    requests_mock.post(
        "http://localhost:8080/stores/foo/batch-check",
        additional_matcher=match_batch_request,
        json={"result": {"d1": {"allowed": False}, "d2": {"allowed": False}}},
    )
    assert not driver.check_system_grant("reader_role_id", "foo", "bar", False)


def test_delete_system_grant(monkeypatch, requests_mock, config):
    driver = plugin.OpenFGA()

    def match_delete_user(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "object": "system:bar",
                        "relation": "reader",
                        "user": "user:foo",
                    }
                ]
            }
        } == request.json()

    def match_delete_group(request):
        return {
            "deletes": {
                "tuple_keys": [
                    {
                        "object": "system:bar",
                        "relation": "reader",
                        "user": "group:foo",
                    }
                ]
            }
        } == request.json()

    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_delete_user,
        status_code=400,
    )
    requests_mock.post(
        "http://localhost:8080/stores/foo/write",
        additional_matcher=match_delete_group,
        status_code=200,
    )
    driver.delete_system_grant("reader_role_id", "foo", "bar", False)
    # None found
    requests_mock.post(
        "http://localhost:8080/stores/foo/write", status_code=400
    )
    with pytest.raises(exception.RoleAssignmentNotFound):
        driver.delete_system_grant("reader_role_id", "foo", "bar", False)
