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

import json
import openstack
import pytest


@pytest.fixture
def admin_connection():
    return openstack.connect("admin")


class TestRoleAssignments:
    def test_list_role_assignments(self, admin_connection):
        # Try listing all direct assignments
        assert list(admin_connection.identity.role_assignments())

        # Try list effective assignments
        assert list(admin_connection.identity.role_assignments(effective=True))

        # For every user try listing role assignments
        for user in admin_connection.identity.users():
            # It is well possible the user has no role assignments, so do not
            # check the result, just ensure there is no crash
            list(
                admin_connection.identity.role_assignments(
                    effective=True, user_id=user.id
                )
            )

    def test_assign_revoke_role_on_project(self, admin_connection):
        user = admin_connection.identity.create_user(
            name="test", password="test", domain_id="default"
        )

        project = admin_connection.identity.create_project(
            name="test_project", domain_id="default"
        )

        member_role = admin_connection.identity.find_role("member")
        reader_role = admin_connection.identity.find_role("reader")

        admin_connection.identity.assign_project_role_to_user(
            project, user, member_role
        )
        assert [member_role.name] == [
            assignment["role"]["name"]
            for assignment in admin_connection.identity.role_assignments(
                user_id=user.id, include_names=True
            )
        ]

        user_connect = admin_connection.connect_as(
            username="test", password="test", project_id=project.id
        )
        # auth is lazy in openstacksdk, so force it
        user_connect.authorize()
        user_auth = json.loads(
            user_connect.config.get_auth().get_auth_state()
        )["body"]["token"]

        assert member_role.name in [
            role["name"] for role in user_auth["roles"]
        ]

        admin_connection.identity.unassign_project_role_from_user(
            project, user, member_role
        )
        admin_connection.identity.assign_project_role_to_user(
            project, user, reader_role
        )
        assert [reader_role.name] == [
            assignment["role"]["name"]
            for assignment in admin_connection.identity.role_assignments(
                user_id=user.id, include_names=True
            )
        ]
        assert admin_connection.identity.validate_user_has_project_role(
            project, user, reader_role
        )
        assert not admin_connection.identity.validate_user_has_project_role(
            project, user, member_role
        )
