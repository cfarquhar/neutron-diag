# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import functools

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron.agent import firewall
from neutron.common import constants as common_constants
from neutron.conf.agent import securitygroups_rpc as sc_cfg


LOG = logging.getLogger(__name__)


sc_cfg.register_securitygroups_opts()


def is_firewall_enabled():
    return cfg.CONF.SECURITYGROUP.enable_security_group


def _disable_extension(extension, aliases):
    if extension in aliases:
        aliases.remove(extension)


def disable_security_group_extension_by_config(aliases):
    if not is_firewall_enabled():
        LOG.info('Disabled security-group extension.')
        _disable_extension('security-group', aliases)
        LOG.info('Disabled allowed-address-pairs extension.')
        _disable_extension('allowed-address-pairs', aliases)


class SecurityGroupAgentRpc(object):
    """Enables SecurityGroup agent support in agent implementations."""

    def __init__(self, context, plugin_rpc, local_vlan_map=None,
                 defer_refresh_firewall=False, integration_bridge=None):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.init_firewall(defer_refresh_firewall, integration_bridge)
        #LOG.info("cfarquhar: SecurityGroupAgentRpc.__init__ context: {}".format(vars(self.context)))

    def _get_trusted_devices(self, device_ids, devices):
        trusted_devices = []
        # Devices which are already added in firewall ports should
        # not be treated as trusted devices but as regular ports
        all_devices = devices.copy()
        all_devices.update(self.firewall.ports)
        device_names = [
            dev['device'] for dev in all_devices.values()]
        for device_id in device_ids:
            if (device_id not in all_devices.keys() and
                    device_id not in device_names):
                trusted_devices.append(device_id)
        return trusted_devices

    def init_firewall(self, defer_refresh_firewall=False,
                      integration_bridge=None):
        firewall_driver = cfg.CONF.SECURITYGROUP.firewall_driver or 'noop'
        LOG.debug("Init firewall settings (driver=%s)", firewall_driver)
        firewall_class = firewall.load_firewall_driver_class(firewall_driver)
        try:
            self.firewall = firewall_class(
                integration_bridge=integration_bridge)
        except TypeError:
            self.firewall = firewall_class()
        # The following flag will be set to true if port filter must not be
        # applied as soon as a rule or membership notification is received
        self.defer_refresh_firewall = defer_refresh_firewall
        # Stores devices for which firewall should be refreshed when
        # deferred refresh is enabled.
        self.devices_to_refilter = set()
        # Flag raised when a global refresh is needed
        self.global_refresh_firewall = False
        self._use_enhanced_rpc = None

    @property
    def use_enhanced_rpc(self):
        if self._use_enhanced_rpc is None:
            self._use_enhanced_rpc = (
                self._check_enhanced_rpc_is_supported_by_server())
        return self._use_enhanced_rpc

    def _check_enhanced_rpc_is_supported_by_server(self):
        try:
            self.plugin_rpc.security_group_info_for_devices(
                self.context, devices=[])
        except oslo_messaging.UnsupportedVersion:
            LOG.warning('security_group_info_for_devices rpc call not '
                        'supported by the server, falling back to old '
                        'security_group_rules_for_devices which scales '
                        'worse.')
            return False
        return True

    def skip_if_noopfirewall_or_firewall_disabled(func):
        @functools.wraps(func)
        def decorated_function(self, *args, **kwargs):
            if (isinstance(self.firewall, firewall.NoopFirewallDriver) or
                    not is_firewall_enabled()):
                LOG.info("Skipping method %s as firewall is disabled "
                         "or configured as NoopFirewallDriver.",
                         func.__name__)
            else:
                return func(self,  # pylint: disable=not-callable
                            *args, **kwargs)
        return decorated_function

    @skip_if_noopfirewall_or_firewall_disabled
    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info("Preparing filters for devices %s", device_ids)
        self._apply_port_filter(device_ids)

    def _apply_port_filter(self, device_ids, update_filter=False):
        step = common_constants.AGENT_RES_PROCESSING_STEP
        LOG.info("entered _apply_port_filter with the following device_ids: {}".format(device_ids))
        if self.use_enhanced_rpc:
            devices = {}
            security_groups = {}
            security_group_member_ips = {}
            for i in range(0, len(device_ids), step):
                LOG.info("cfarquhar: in _apply_port_filter, calling security_group_info_for_devices for {}".format(list(device_ids)[i:i + step]))
                devices_info = self.plugin_rpc.security_group_info_for_devices(
                    self.context, list(device_ids)[i:i + step])
                devices.update(devices_info['devices'])
                security_groups.update(devices_info['security_groups'])
                security_group_member_ips.update(devices_info['sg_member_ips'])
        else:
            LOG.info("cfarquhar: in _apply_port_filter, not using enhanced_rpc - NOT EXPECTED")
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, list(device_ids))
        trusted_devices = self._get_trusted_devices(device_ids, devices)
        

        with self.firewall.defer_apply():
            LOG.info("cfarquhar: entered _apply_port_filter's 'with self.firewall.defer_apply()'")
            if self.use_enhanced_rpc:
                LOG.debug("Update security group information for ports %s",
                          devices.keys())
                LOG.debug("cfarquhar: in _apply_port_filter, calling _update_security_group_info for (secgroup, secgroup_member_ips) {} {}".format(security_groups, security_group_member_ips))
                self._update_security_group_info(
                    security_groups, security_group_member_ips)
            for device in devices.values():
                if update_filter:
                    LOG.info("cfarquhar: in _apply_port_filter, Update port filter for %s", device['device'])
                    self.firewall.update_port_filter(device)
                else:
                    LOG.info("cfarquhar: in _apply_port_filter, Prepare port filter for %s", device['device'])
                    self.firewall.prepare_port_filter(device)
            LOG.info("cfarquhar: in _apply_port_filter, calling process_trusted_ports with trusted_devices = {}".format(trusted_devices))
            self.firewall.process_trusted_ports(trusted_devices)

    def _update_security_group_info(self, security_groups,
                                    security_group_member_ips):
        LOG.debug("Update security group information")
        LOG.info("cfarquhar: entered _update_security_group_info with security_groups = {}, security_group_member_ips = {}".format(security_groups, security_group_member_ips))
        LOG.info("cfarquhar: (usgr) calling firewall.update_security_group_rules for the following (sg, rules):")
        for sg_id, sg_rules in security_groups.items():
            LOG.info("cfarquhar: (usgr) {} {}".format(sg_id, sg_rules))
            self.firewall.update_security_group_rules(sg_id, sg_rules)
        LOG.info("cfarquhar: (usgm) calling firewall.update_security_group_members for the following (remote_sg, member_ips):")
        for remote_sg_id, member_ips in security_group_member_ips.items():
            LOG.info("cfarquhar: (usgm) {} {}".format(remote_sg_id, member_ips))
            self.firewall.update_security_group_members(
                remote_sg_id, member_ips)

    def security_groups_rule_updated(self, security_groups):
        LOG.info("Security group "
                 "rule updated %r", security_groups)
        self._security_group_updated(
            security_groups,
            'security_groups',
            'sg_rule')

    def security_groups_member_updated(self, security_groups):
        LOG.info("Security group "
                 "member updated %r", security_groups)
        LOG.info("cfarquhar: entered security_groups_member_updated.")
        # LOG.info("cfarquhar: in security_groups_member_updated.  Stack trace:")
        # import traceback
        # stack_layer = 0
        # for stackitem in traceback.extract_stack():
        #     LOG.info("cfarquhar: {}: {}".format(stack_layer, stackitem))
        #     stack_layer += 1
        self._security_group_updated(
            security_groups,
            'security_group_source_groups',
            'sg_member')

    def _security_group_updated(self, security_groups, attribute, action_type):
        LOG.info("cfarquhar: entered _security_group_updated with security_groups = {}, attribute = {}, action_type = {}".format(security_groups, attribute, action_type))
        devices = []
        sec_grp_set = set(security_groups)
        for device in self.firewall.ports.values():
            LOG.info("cfarquhar: (_security_group_updated) looking for intersection of src_grp_set {} and {}'s {}: {}".format(sec_grp_set, device['device'], attribute, set(device.get(attribute, []))))
            if sec_grp_set & set(device.get(attribute, [])):
                # LOG.info("cfarquhar: appending device {}".format(device))
                devices.append(device['device'])
                LOG.info("cfarquhar: (_security_group_updated) found intersection {}, appending device {}".format(sec_grp_set & set(device.get(attribute, [])), device['device']))
            else:
                LOG.info("cfarquhar: (_security_group_updated) no intersection found.  not appending device {}".format(device['device']))
        if devices:
            LOG.info("cfarquhar: (_security_group_updated) entered devices branch with {}".format(devices))
            if self.use_enhanced_rpc:
                LOG.info("cfarquhar: use_enhanced_rpc = true")
                LOG.info("cfarquhar: (_security_group_updated) calling firewall.security_group_updated with action_type {} and sec_grp_set {}".format(action_type, sec_grp_set))
                self.firewall.security_group_updated(action_type, sec_grp_set)
            else:
                LOG.info("cfarquhar: use_enhanced_rpc = false")
            if self.defer_refresh_firewall:
                LOG.debug("Adding %s devices to the list of devices "
                          "for which firewall needs to be refreshed",
                          devices)
                LOG.info("cfarquhar: defer_refresh_firewall = true")
                LOG.info("cfarquhar: (_security_group_updated) devices to refilter BEFORE: {}".format(self.devices_to_refilter))
                self.devices_to_refilter |= set(devices)
                LOG.info("cfarquhar: (_security_group_updated) devices to refilter AFTER: {}".format(self.devices_to_refilter))
            else:
                LOG.info("cfarquhar: defer_refresh_firewall = false")
                self.refresh_firewall(devices)
        else:
            LOG.info("cfarquhar: (_security_group_updated) device list was empty")

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info("Remove device filter for %r", device_ids)
        with self.firewall.defer_apply():
            for device_id in device_ids:
                device = self.firewall.ports.get(device_id)
                if device:
                    self.firewall.remove_port_filter(device)
                else:
                    self.firewall.remove_trusted_ports([device_id])

    @skip_if_noopfirewall_or_firewall_disabled
    def refresh_firewall(self, device_ids=None):
        LOG.info("Refresh firewall rules")
        LOG.info("cfarquhar: entering refresh_firewall")
        # LOG.info("cfarquhar: how did we arrive?")
        # import traceback
        # stack_layer = 0
        # for stackitem in traceback.extract_stack():
        #     LOG.info("cfarquhar: {}: {}".format(stack_layer, stackitem))
        #     stack_layer += 1
        if not device_ids:
            device_ids = self.firewall.ports.keys()
            if not device_ids:
                LOG.info("No ports here to refresh firewall")
                return
        self._apply_port_filter(device_ids, update_filter=True)

    def firewall_refresh_needed(self):
        return self.global_refresh_firewall or self.devices_to_refilter

    def setup_port_filters(self, new_devices, updated_devices):
        """Configure port filters for devices.

        This routine applies filters for new devices and refreshes firewall
        rules when devices have been updated, or when there are changes in
        security group membership or rules.

        :param new_devices: set containing identifiers for new devices
        :param updated_devices: set containing identifiers for
        updated devices
        """
        # These data structures are cleared here in order to avoid
        # losing updates occurring during firewall refresh
        devices_to_refilter = self.devices_to_refilter
        global_refresh_firewall = self.global_refresh_firewall
        self.devices_to_refilter = set()
        self.global_refresh_firewall = False
        # We must call prepare_devices_filter() after we've grabbed
        # self.devices_to_refilter since an update for a new port
        # could arrive while we're processing, and we need to make
        # sure we don't skip it.  It will get handled the next time.
        if new_devices:
            LOG.debug("Preparing device filters for %d new devices",
                      len(new_devices))
            self.prepare_devices_filter(new_devices)
        # TODO(salv-orlando): Avoid if possible ever performing the global
        # refresh providing a precise list of devices for which firewall
        # should be refreshed
        if global_refresh_firewall:
            LOG.debug("Refreshing firewall for all filtered devices")
            self.refresh_firewall()
        else:
            if self.use_enhanced_rpc and updated_devices:
                self.firewall.security_group_updated('sg_member', [],
                                                     updated_devices)
            # If a device is both in new and updated devices
            # avoid reprocessing it
            updated_devices = ((updated_devices | devices_to_refilter) -
                               new_devices)
            if updated_devices:
                LOG.debug("Refreshing firewall for %d devices",
                          len(updated_devices))
                self.refresh_firewall(updated_devices)
