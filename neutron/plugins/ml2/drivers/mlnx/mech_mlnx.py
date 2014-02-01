# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo.config import cfg

from neutron.common import constants
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2.drivers.mlnx import config  # noqa

LOG = log.getLogger(__name__)


class MlnxMechanismDriver(mech_agent.AgentMechanismDriverBase):
    """Attach to networks using Mellanox eSwitch L2 agent.

    The MellanoxMechanismDriver integrates the ml2 plugin with the
    Mellanox eswitch L2 agent. Port binding with this driver requires the
    Mellanox eswitch  agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """

    def __init__(self):
        super(MlnxMechanismDriver, self).__init__(
            constants.AGENT_TYPE_MLNX,
            cfg.CONF.ESWITCH.vnic_type,
            True)

    def check_segment_for_agent(self, segment, agent):
        mappings = agent['configurations'].get('interface_mappings', {})
        LOG.debug(_("Checking segment: %(segment)s "
                    "for mappings: %(mappings)s "),
                  {'segment': segment, 'mappings': mappings})
        network_type = segment[api.NETWORK_TYPE]
        if network_type == 'local':
            return True
        elif network_type in ['flat', 'vlan']:
            return segment[api.PHYSICAL_NETWORK] in mappings
        else:
            return False
