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

from oslo_config import cfg
from oslo_config import types

openfga_group = cfg.OptGroup(
    name="fga", title="Options for OpenFGA role assignment backend"
)

openfga_opts = [
    cfg.StrOpt("api_url", help="OpenFGA server URL"),
    cfg.StrOpt("store_id", help="OpenFGA store ID"),
    cfg.StrOpt("model_id", help="OpenFGA model ID"),
    cfg.BoolOpt("verify", default=True, help="Verify SSL certificate"),
    cfg.ListOpt(
        "domains_using_sql_backend",
        item_type=types.String,
        help="Use SQL backend for domains in a list",
    ),
]


def register_opts(conf):
    conf.register_group(openfga_group)
    conf.register_opts(openfga_opts, group=openfga_group)
