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

import typing as ty

import keystone.conf
import oslo_config
from keystone import exception
from keystone.assignment.backends import base, sql
from keystone.common import provider_api
from oslo_log import log

from keystone_role_assignment_openfga import config
from keystone_role_assignment_openfga.plugin import OpenFGA

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class OpenFGASqlMultiplex(base.AssignmentDriverBase):
    conf: oslo_config.cfg.ConfigOpts

    @classmethod
    def default_role_driver(cls) -> str:
        return "sql"

    def __init__(self):
        super().__init__()

        self.conf = CONF
        config.register_opts(self.conf)
        self.openfga = OpenFGA()
        self.sql = sql.Assignment()

    def should_use_sql_backend(
        self,
        user_id: ty.Optional[str] = None,
        group_id: ty.Optional[str] = None,
        project_id: ty.Optional[str] = None,
        domain_id: ty.Optional[str] = None,
    ) -> bool:
        """Determine whether SQL backend driver should be used"""
        use_sql = False
        if user_id:
            user = PROVIDERS.identity_api.get_user(user_id)
            if (
                user.get("domain_id")
                in self.conf.fga.domains_using_sql_backend
            ):
                use_sql = True
        elif group_id:
            group = PROVIDERS.identity_api.get_group(group_id)
            if (
                group.get("domain_id")
                in self.conf.fga.domains_using_sql_backend
            ):
                use_sql = True
        elif project_id:
            project = PROVIDERS.resource_api.get_project(project_id)
            if (
                project.get("domain_id")
                in self.conf.fga.domains_using_sql_backend
            ):
                use_sql = True
        elif domain_id:
            if domain_id in self.conf.fga.domains_using_sql_backend:
                use_sql = True
        return use_sql

    # assignment/grant crud

    def add_role_to_user_and_project(self, user_id, project_id, role_id):
        """Add a role to a user within given project.

        :raises keystone.exception.Conflict: If a duplicate role assignment
            exists.

        """
        if self.should_use_sql_backend(user_id=user_id, project_id=project_id):
            self.sql.add_role_to_user_and_project(user_id, project_id, role_id)
        else:
            self.openfga.add_role_to_user_and_project(
                user_id, project_id, role_id
            )

    def remove_role_from_user_and_project(self, user_id, project_id, role_id):
        """Remove a role from a user within given project.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        if self.should_use_sql_backend(user_id=user_id, project_id=project_id):
            self.sql.remove_role_from_user_and_project(
                user_id, project_id, role_id
            )
        else:
            self.openfga.remove_role_from_user_and_project(
                user_id, project_id, role_id
            )

    def create_grant(
        self,
        role_id,
        user_id=None,
        group_id=None,
        domain_id=None,
        project_id=None,
        inherited_to_projects=False,
    ):
        """Create a new assignment/grant.

        If the assignment is to a domain, then optionally it may be
        specified as inherited to owned projects (this requires
        the OS-INHERIT extension to be enabled).

        """
        if not self.should_use_sql_backend(
            user_id=user_id,
            group_id=group_id,
            domain_id=domain_id,
            project_id=project_id,
        ):
            self.openfga.create_grant(
                role_id,
                user_id=user_id,
                group_id=group_id,
                domain_id=domain_id,
                project_id=project_id,
                inherited_to_projects=inherited_to_projects,
            )
        else:
            self.sql.create_grant(
                role_id,
                user_id=user_id,
                group_id=group_id,
                domain_id=domain_id,
                project_id=project_id,
                inherited_to_projects=inherited_to_projects,
            )

    def list_grant_role_ids(
        self,
        user_id=None,
        group_id=None,
        domain_id=None,
        project_id=None,
        inherited_to_projects=False,
    ):
        """List role ids for assignments/grants."""
        if not self.should_use_sql_backend(
            user_id=user_id,
            group_id=group_id,
            domain_id=domain_id,
            project_id=project_id,
        ):
            return self.openfga.list_grant_role_ids(
                user_id=user_id,
                group_id=group_id,
                domain_id=domain_id,
                project_id=project_id,
                inherited_to_projects=inherited_to_projects,
            )
        else:
            return self.sql.list_grant_role_ids(
                user_id=user_id,
                group_id=group_id,
                domain_id=domain_id,
                project_id=project_id,
                inherited_to_projects=inherited_to_projects,
            )

    def check_grant_role_id(
        self,
        role_id,
        user_id=None,
        group_id=None,
        domain_id=None,
        project_id=None,
        inherited_to_projects=False,
    ):
        """Check an assignment/grant role id.

        :raises keystone.exception.RoleAssignmentNotFound: If the role
            assignment doesn't exist.
        :returns: None or raises an exception if grant not found

        """
        if not self.should_use_sql_backend(
            user_id=user_id,
            group_id=group_id,
            domain_id=domain_id,
            project_id=project_id,
        ):
            return self.openfga.check_grant_role_id(
                role_id,
                user_id=user_id,
                group_id=group_id,
                project_id=project_id,
                domain_id=domain_id,
                inherited_to_projects=inherited_to_projects,
            )
        else:
            return self.sql.check_grant_role_id(
                role_id,
                user_id=user_id,
                group_id=group_id,
                project_id=project_id,
                domain_id=domain_id,
                inherited_to_projects=inherited_to_projects,
            )

    def delete_grant(
        self,
        role_id,
        user_id=None,
        group_id=None,
        domain_id=None,
        project_id=None,
        inherited_to_projects=False,
    ):
        """Delete assignments/grants.

        :raises keystone.exception.RoleAssignmentNotFound: If the role
            assignment doesn't exist.

        """
        if not self.should_use_sql_backend(
            user_id=user_id,
            group_id=group_id,
            domain_id=domain_id,
            project_id=project_id,
        ):
            return self.openfga.delete_grant(
                role_id,
                user_id=user_id,
                group_id=group_id,
                project_id=project_id,
                domain_id=domain_id,
                inherited_to_projects=inherited_to_projects,
            )
        else:
            return self.sql.delete_grant(
                role_id,
                user_id=user_id,
                group_id=group_id,
                project_id=project_id,
                domain_id=domain_id,
                inherited_to_projects=inherited_to_projects,
            )

    def list_role_assignments(
        self,
        role_id=None,
        user_id=None,
        group_ids=None,
        domain_id=None,
        project_ids=None,
        inherited_to_projects=None,
    ):
        """Return a list of role assignments for actors on targets.

        Available parameters represent values in which the returned role
        assignments attributes need to be filtered on.

        """
        if not self.should_use_sql_backend(
            user_id=user_id,
            group_id=group_id,
            domain_id=domain_id,
            project_id=project_id,
        ):
            return self.openfga.list_role_assignments(
                role_id=role_id,
                user_id=user_id,
                group_id=group_id,
                project_id=project_id,
                domain_id=domain_id,
                inherited_to_projects=inherited_to_projects,
            )
        else:
            return self.sql.list_role_assignments(
                role_id=role_id,
                user_id=user_id,
                group_id=group_id,
                project_id=project_id,
                domain_id=domain_id,
                inherited_to_projects=inherited_to_projects,
            )

    def delete_project_assignments(self, project_id):
        """Delete all assignments for a project.

        :raises keystone.exception.ProjectNotFound: If the project doesn't
            exist.

        """
        if not self.should_use_sql_backend(project_id=project_id):
            return self.openfga.delete_project_assignments(project_id)
        else:
            return self.sql.delete_project_assignments(project_id)

    def delete_role_assignments(self, role_id):
        """Delete all assignments for a role."""
        if not self.should_use_sql_backend(project_id=project_id):
            raise exception.NotImplemented()  # pragma: no cover
        else:
            return self.sql.list_role_assignments(role_id)

    def delete_user_assignments(self, user_id):
        """Delete all assignments for a user.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        if not self.should_use_sql_backend(user_id=user_id):
            return self.openfga.delete_user_assignments(user_id)
        else:
            return self.sql.delete_user_assignments(user_id)

    def delete_group_assignments(self, group_id):
        """Delete all assignments for a group.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        if not self.should_use_sql_backend(group_id=group_id):
            return self.openfga.delete_group_assignments(group_id)
        else:
            return self.sql.delete_group_assignments(group_id)

    def delete_domain_assignments(self, domain_id):
        """Delete all assignments for a domain."""
        if not self.should_use_sql_backend(domain_id=domain_id):
            return self.openfga.delete_domain_assignments(domain_id)
        else:
            return self.sql.delete_domain_assignments(domain_id)

    def create_system_grant(
        self, role_id, actor_id, target_id, assignment_type, inherited
    ):
        """Grant a user or group  a role on the system.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param assignment_type: a string describing the relationship of the
            assignment
        :param inherited: a boolean denoting if the assignment is inherited or
            not
        """
        user_id: ty.Optional[str] = None
        group_id: ty.Optional[str] = None
        if assignment_type == "UserSystem":
            user_id = actor_id
        elif assignment_type == "GroupSystem":
            group_id = actor_id
        if not self.should_use_sql_backend(user_id=user_id, group_id=group_id):
            return self.openfga.create_system_grant(
                role_id, actor_id, target_id, assignment_type, inherited
            )
        else:
            return self.sql.create_system_grant(
                role_id, actor_id, target_id, assignment_type, inherited
            )

    def list_system_grants(self, actor_id, target_id, assignment_type):
        """Return a list of all system assignments for a specific entity.

        :param actor_id: the unique ID of the actor
        :param target_id: the unique ID of the target
        :param assignment_type: the type of assignment to return

        """
        user_id: ty.Optional[str] = None
        group_id: ty.Optional[str] = None
        if assignment_type == "UserSystem":
            user_id = actor_id
        elif assignment_type == "GroupSystem":
            group_id = actor_id
        if not self.should_use_sql_backend(user_id=user_id, group_id=group_id):
            return self.openfga.list_system_grants(
                actor_id, target_id, assignment_type
            )
        else:
            return self.sql.create_system_grant(
                actor_id, target_id, assignment_type
            )

    def list_system_grants_by_role(self, role_id):
        """Return a list of system assignments associated to a role.

        :param role_id: the unique ID of the role to grant to the user

        """
        # NOTE(gtema) It is not possible to figure out whether we should use
        # OpenFGA or SQL backend based only on role_id. The API should be also
        # not really used in the Keystone.
        raise exception.NotImplemented()  # pragma: no cover

    def check_system_grant(self, role_id, actor_id, target_id, inherited):
        """Check if a user or group has a specific role on the system.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param inherited: a boolean denoting if the assignment is inherited or
            not

        """
        use_sql = False
        try:
            user = PROVIDERS.identity_api.get_user(actor_id)
            if (
                user.get("domain_id")
                in self.conf.fga.domains_using_sql_backend
            ):
                use_sql = True
        except exception.NotFound:
            try:
                group = PROVIDERS.identity_api.get_group(actor_id)
                if (
                    group.get("domain_id")
                    in self.conf.fga.domains_using_sql_backend
                ):
                    use_sql = True
            except exception.NotFound:
                raise exception.NotImplemented()  # pragma: no cover
        if not use_sql:
            return self.openfga.check_system_grant(
                role_id, actor_id, target_id, inherited
            )
        else:
            return self.sql.check_system_grant(
                role_id, actor_id, target_id, inherited
            )

    def delete_system_grant(self, role_id, actor_id, target_id, inherited):
        """Remove a system assignment from a user or group.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param inherited: a boolean denoting if the assignment is inherited or
            not

        """
        use_sql = False
        try:
            user = PROVIDERS.identity_api.get_user(actor_id)
            if (
                user.get("domain_id")
                in self.conf.fga.domains_using_sql_backend
            ):
                use_sql = True
        except exception.NotFound:
            try:
                group = PROVIDERS.identity_api.get_group(actor_id)
                if (
                    group.get("domain_id")
                    in self.conf.fga.domains_using_sql_backend
                ):
                    use_sql = True
            except exception.NotFound:
                raise exception.NotImplemented()  # pragma: no cover
        if not use_sql:
            return self.openfga.delete_system_grant(
                role_id, actor_id, target_id, inherited
            )
        else:
            return self.sql.delete_system_grant(
                role_id, actor_id, target_id, inherited
            )
