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
import requests
from keystone import exception
from keystone.assignment.backends import base
from keystone.common import provider_api
from oslo_log import log

from keystone_role_assignment_openfga import config

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


def convert_openfga_to_assignment_base(actor: str, target: str):
    """Convert actor and target to the assignment dict."""
    assignment: dict[str, str] = {}
    if actor.startswith("user"):
        assignment["user_id"] = actor[5:]
    elif actor.startswith("group"):
        assignment["group_id"] = actor[5:]
    if target.startswith("project"):
        assignment["project_id"] = target[8:]
    elif target.startswith("group"):
        assignment["group_id"] = target[6:]
    elif target.startswith("system"):
        assignment["system_id"] = target[6:]
    return assignment


def convert_openfga_tuple_to_assignment(
    fga_tuple, roles_by_name
) -> ty.Optional[dict[str, str]]:
    """Convert OpenFGA tuple data to the role assignment dict"""
    assignment: dict = convert_openfga_to_assignment_base(
        fga_tuple["user"], fga_tuple["object"]
    )
    fga_relation = fga_tuple["relation"]
    if fga_relation in roles_by_name:
        assignment["role_id"] = roles_by_name[fga_relation]
    else:
        return None
    return assignment


class OpenFGA(base.AssignmentDriverBase):
    conf: oslo_config.cfg.ConfigOpts
    _openfga: requests.Session
    roles_by_name: dict[str, str] = {}
    roles_by_id: dict[str, str] = {}

    @classmethod
    def default_role_driver(cls) -> str:
        return "sql"

    def __init__(self):
        super().__init__()

        self.conf = CONF
        config.register_opts(self.conf)
        self.openfga = requests.Session()

    def _get_roles_by_name(self):
        if not self.roles_by_name:
            self.roles_by_name = {
                x["name"]: x["id"] for x in PROVIDERS.role_api.list_roles()
            }
        return self.roles_by_name

    def _get_roles_by_id(self):
        if not self.roles_by_id:
            self.roles_by_id = {
                v: k for k, v in self._get_roles_by_name().items()
            }
        return self.roles_by_id

    @property
    def fga_session(self):
        if not hasattr(self, "_openfga"):
            self._openfga = requests.Session()
        return self._openfga

    def openfga_read_tuples(self, query: dict) -> list[dict]:
        """Perform `read tuples` OpenFGA request"""
        assignments: list[dict[str, str]] = []
        try:
            LOG.debug(f"Querying OpenFGA with {query}")
            request: dict = {"tuple_key": query} if query else {}
            response = self.fga_session.post(
                f"{self.conf.fga.api_url}/stores/{self.conf.fga.store_id}/read",
                json=request,
            )
            if response.status_code != 200:
                LOG.warning(
                    "failed to check authorization (invalid http code: %s, body: %s",
                    response.status_code,
                    response.text,
                )
                return []
            data = response.json().get("tuples", None)
            LOG.debug(f"OpenFGA response: {data}")
            for fga_tuple in data:
                assignment = convert_openfga_tuple_to_assignment(
                    fga_tuple.get("key"), self._get_roles_by_name()
                )
                if assignment:
                    assignments.append(assignment)

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
        ) as ex:
            LOG.warning(
                "failed to read authorization tuples in OpenFGA: %s", ex
            )
            raise

        return assignments

    def openfga_check(self, query: dict) -> bool:
        """Perform `check` OpenFGA request"""
        assignments: list[dict[str, str]] = []
        try:
            LOG.debug(f"Check OpenFGA authorizations with {query}")
            response = self.fga_session.post(
                f"{self.conf.fga.api_url}/stores/{self.conf.fga.store_id}/check",
                json={"tuple_key": query},
            )
            if response.status_code != 200:
                LOG.warning(
                    "failed to check authorization (invalid http code: %s, body: %s",
                    response.status_code,
                    response.text,
                )
                return False
            LOG.debug(f"OpenFGA response: {response.json()}")
            allowed = response.json().get("allowed", None)
            if allowed is not None:
                return allowed
            else:
                LOG.warning(
                    "Allowed flag was not present in the OpenFGA check response"
                )

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
        ) as ex:
            LOG.warning("failed to check authorization in OpenFGA: %s", ex)
            raise

        return False

    def openfga_check_actor_object_relations(
        self, actor: str, target: str
    ) -> list[dict[str, str]]:
        """Perform `batch_check` OpenFGA request to fetch all relevant relations (role assignments)"""
        assignments: list[dict[str, str]] = []
        query: dict[str, ty.Any] = {"checks": []}
        for role_name, role_id in self._get_roles_by_name().items():
            query["checks"].append(
                {
                    "tuple_key": {
                        "user": actor,
                        "object": target,
                        "relation": role_name,
                    },
                    "correlation_id": role_id,
                }
            )

        try:
            LOG.debug(f"Batch Check OpenFGA authorizations with {query}")
            response = self.fga_session.post(
                f"{self.conf.fga.api_url}/stores/{self.conf.fga.store_id}/batch-check",
                json=query,
            )
            if response.status_code != 200:
                LOG.warning(
                    "failed to batch check authorization (invalid http code: %s, body: %s",
                    response.status_code,
                    response.text,
                )
                return assignments
            LOG.debug(f"OpenFGA response: {response.json()}")
            check_results = response.json()["result"]

            for role_name, role_id in self._get_roles_by_name().items():
                role_result = check_results.get(role_id, None)
                if role_result:
                    if role_result.get("allowed", False):
                        assignment: dict = convert_openfga_to_assignment_base(
                            actor, target
                        )
                        assignment["role_id"] = role_id
                        assignments.append(assignment)

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
        ) as ex:
            LOG.warning("failed to check authorization in OpenFGA: %s", ex)
            raise

        return assignments

    def add_role_to_user_and_project(self, user_id, project_id, role_id):
        """Add a role to a user within given project.

        :raises keystone.exception.Conflict: If a duplicate role assignment
            exists.

        """
        raise exception.NotImplemented()  # pragma: no cover

    def remove_role_from_user_and_project(self, user_id, project_id, role_id):
        """Remove a role from a user within given project.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    # assignment/grant crud

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
        raise exception.NotImplemented()  # pragma: no cover

    def list_grant_role_ids(
        self,
        user_id=None,
        group_id=None,
        domain_id=None,
        project_id=None,
        inherited_to_projects=False,
    ):
        """List role ids for assignments/grants."""
        fga_read_tuples_request: dict[str, str] = {}
        if project_id:
            fga_read_tuples_request["object"] = f"project:{project_id}"
        elif domain_id:
            fga_read_tuples_request["object"] = f"domain:{domain_id}"

        if user_id:
            fga_read_tuples_request["user"] = f"user:{user_id}"
        elif group_id:
            fga_read_tuples_request["user"] = f"group:{group_id}"

        assignments: list[dict] = self.openfga_read_tuples(
            fga_read_tuples_request
        )
        return [x["role_id"] for x in assignments]

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
        fga_check_request: dict[str, str] = {}
        target_id: ty.Optional[str] = project_id or domain_id
        actor_id: ty.Optional[str] = user_id or group_id

        if project_id:
            fga_check_request["object"] = f"project:{project_id}"
        elif domain_id:
            fga_check_request["object"] = f"domain:{domain_id}"

        if user_id:
            fga_check_request["user"] = f"user:{user_id}"
        elif group_id:
            fga_check_request["user"] = f"group:{group_id}"

        relation = PROVIDERS.role_api.get_role(role_id)["name"]
        if relation:
            fga_check_request["relation"] = relation

        if not self.openfga_check(fga_check_request):
            raise exception.RoleAssignmentNotFound(
                role_id=role_id, actor_id=actor_id, target_id=target_id
            )
        return

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
        raise exception.NotImplemented()  # pragma: no cover

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
        fga_read_tuples_request: dict[str, str] = {}
        actor: ty.Optional[str] = None
        target: ty.Optional[str] = None
        if project_ids:
            if len(project_ids) > 1:
                raise exception.NotImplemented(
                    "Listing role assignments for multiple project_ids is not implemented"
                )
            target = f"project:{project_ids[0]}"
        elif domain_id:
            target = f"domain:{domain_id}"
        if target:
            fga_read_tuples_request["object"] = target

        if user_id:
            fga_read_tuples_request["user"] = f"user:{user_id}"
            actor = f"user:{user_id}"
        elif group_ids:
            if len(group_ids) > 1:
                raise exception.NotImplemented(
                    "Listing role assignments for multiple group_ids is not implemented"
                )  # pragma: no cover
            fga_read_tuples_request["user"] = f"group:{group_ids[0]}"
            actor = f"group:{group_ids[0]}"
        if actor:
            fga_read_tuples_request["user"] = actor

        if role_id and (target or actor):
            # Filter to the specific relation (role)
            fga_read_tuples_request["relation"] = PROVIDERS.role_api.get_role(
                role_id
            )["name"]

        assignments: list[dict[str, str]] = []
        if user_id and target and not role_id:
            # User authorization attempt has a combination of user_id and
            # specific target without role. In this case wee want to return
            # list of effective assignments.
            assignments = self.openfga_check_actor_object_relations(
                actor, target
            )
            # TODO: keystone caches user roles so technically we may need to
            # invalidate the cache immediately.
        else:
            assignments = [
                assignment
                for assignment in self.openfga_read_tuples(
                    fga_read_tuples_request
                )
                if not role_id or assignment[role_id] == role_id
            ]
        return assignments

    def delete_project_assignments(self, project_id):
        """Delete all assignments for a project.

        :raises keystone.exception.ProjectNotFound: If the project doesn't
            exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    def delete_role_assignments(self, role_id):
        """Delete all assignments for a role."""
        raise exception.NotImplemented()  # pragma: no cover

    def delete_user_assignments(self, user_id):
        """Delete all assignments for a user.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    def delete_group_assignments(self, group_id):
        """Delete all assignments for a group.

        :raises keystone.exception.RoleNotFound: If the role doesn't exist.

        """
        raise exception.NotImplemented()  # pragma: no cover

    def delete_domain_assignments(self, domain_id):
        """Delete all assignments for a domain."""
        raise exception.NotImplemented()

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
        raise exception.NotImplemented()  # pragma: no cover

    def list_system_grants(self, actor_id, target_id, assignment_type):
        """Return a list of all system assignments for a specific entity.

        :param actor_id: the unique ID of the actor
        :param target_id: the unique ID of the target
        :param assignment_type: the type of assignment to return

        """
        LOG.debug(
            f"Listing system grants of {assignment_type} for {actor_id} on {target_id}"
        )

        fga_read_tuples_request: dict[str, str] = {}
        targets = None
        if actor_id:
            if assignment_type == "UserSystem":
                fga_read_tuples_request["user"] = f"user:{actor_id[0]}"
            elif assignment_type == "GroupSystem":
                fga_read_tuples_request["user"] = f"group:{actor_id[0]}"

        if target_id:
            fga_read_tuples_request["object"] = f"system:{target_id}"

        assignments: list[dict] = self.openfga_read_tuples(
            fga_read_tuples_request
        )
        return assignments

    def list_system_grants_by_role(self, role_id):
        """Return a list of system assignments associated to a role.

        :param role_id: the unique ID of the role to grant to the user

        """
        LOG.debug(f"Listing system grants by for role {role_id}")

        fga_read_tuples_request: dict[str, str] = {}
        targets = None
        fga_read_tuples_request["relation"] = self._get_roles_by_id()[role_id]

        # NOTE(gtema) system scope currently supports a single target_id = 'system'
        fga_read_tuples_request["object"] = f"system:system"

        assignments: list[dict] = self.openfga_read_tuples(
            fga_read_tuples_request
        )
        return assignments

    def check_system_grant(self, role_id, actor_id, target_id, inherited):
        """Check if a user or group has a specific role on the system.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param inherited: a boolean denoting if the assignment is inherited or
                          not

        """
        raise exception.NotImplemented()  # pragma: no cover

    def delete_system_grant(self, role_id, actor_id, target_id, inherited):
        """Remove a system assignment from a user or group.

        :param role_id: the unique ID of the role to grant to the user
        :param actor_id: the unique ID of the user or group
        :param target_id: the unique ID or string representing the target
        :param inherited: a boolean denoting if the assignment is inherited or
                          not

        """
        raise exception.NotImplemented()  # pragma: no cover
