# Copyright 2014 Mellanox Technologies, Ltd
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

import re

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import exceptions as n_exc
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class IpLinkSupportError(n_exc.NeutronException):
    pass


class UnsupportedIpLinkCommand(IpLinkSupportError):
    message = _("ip link command is not supported: %(reason)s")


class InvalidIpLinkCapability(IpLinkSupportError):
    message = _("ip link capability %(capability)s is not supported")


class IpLinkConstants(object):
    IP_LINK_CAPABILITY_STATE = "state"
    IP_LINK_CAPABILITY_VLAN = "vlan"
    IP_LINK_CAPABILITY_RATE = "rate"
    IP_LINK_CAPABILITY_SPOOFCHK = "spoofchk"
    IP_LINK_SUB_CAPABILITY_QOS = "qos"


class IpLinkSupport(ip_lib.IPWrapper):
    IP_LINK_SET_BLOCK_REGEX = "ip link set(?P<set_block>.*)ip link"
    VF_BLOCK_REGEX = "\[ vf NUM(?P<vf_block>.*) \] \]"

    CAPABILITY_REGEX = "\[ %s (.*)"
    SUB_CAPABILITY_REGEX = "\[ %(cap)s (.*) \[ %(subcap)s (.*)"

    def ip_link_capability_supported(self, capability, subcapability=None):
        """Validate capability support

        Checks if ip link support the given capability (and sub capability
        if given
        :param capability: for example: vlan, rate, spoofchk, state
        :param subcapability: for example: qos
        """
        out = self._get_ip_link_output()
        return self._check_ip_link_output(out, capability, subcapability)

    def _get_ip_link_output(self):
        """Gets the output of the ip link help command

        Runs ip link help command and returns its output
        Note: ip link help return error and writes its output to stderr
                so we get the output from there. however, if this issue
                will be solved and the command will write to stdout, we
                will get the output from there too.
        """
        try:
            ip_cmd = ['ip', 'link', 'help']
            _stdout, _stderr = utils.execute(ip_cmd, self.root_helper,
                                             check_exit_code=False,
                                             return_stderr=True)
        except Exception as e:
            LOG.exception(_("Failed executing ip command"))
            raise UnsupportedIpLinkCommand(reason=str(e))

        return _stdout or _stderr

    def _check_ip_link_output(self, out, capability, subcapability):
        """Parses ip link help output, and checks for capability support

        Iterates over all lines in output until it reaches the "ip link set"
        section, then it passes all left lines to parsing "set section" method

        :param out: ip link help output
        :param capability: capability to look for
        :param subcapability: sub-capability to look for
        """
        ip_link_set_section = self._find_set_section(out)
        if not ip_link_set_section:
            return False
        vf_section = self._find_vf_section(out)
        if not vf_section:
            return False
        return self._search_capability(vf_section, capability, subcapability)

    def _find_set_section(self, cmd_output):
        """Searches for the "ip link set" help section

        :param cmd_output: ip link help output
        """
        ip_link_set_pattern = re.search(self.IP_LINK_SET_BLOCK_REGEX,
                                        cmd_output, re.DOTALL | re.MULTILINE)
        if not ip_link_set_pattern:
            return False
        return ip_link_set_pattern.group("set_block")

    def _find_vf_section(self, ip_link_set_section):
        """Searches for the "vf Num" section

        :param ip_link_set_section: ip link set section within the help output
        """
        vf_block_pattern = re.search(self.VF_BLOCK_REGEX,
                                     ip_link_set_section,
                                     re.DOTALL | re.MULTILINE)
        return vf_block_pattern.group("vf_block")

    def _search_capability(self, vf_block, capability, subcapability):
        """Searches for capability and sub-capability within the VF block

        :param vf_block: vf Num block content
        :param capability: capability to look for
        :param subcapability: sub-capability to look for
        """
        if subcapability:
            regex = self.SUB_CAPABILITY_REGEX % {"cap": capability,
                                                 "subcap": subcapability}
        else:
            regex = self.CAPABILITY_REGEX % capability
        pattern_match = re.search(regex, vf_block, re.DOTALL | re.MULTILINE)
        return (pattern_match is not None)
