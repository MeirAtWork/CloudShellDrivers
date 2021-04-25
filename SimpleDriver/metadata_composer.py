#!/usr/bin/env python
import yaml
import json
import ConfigParser
import csv
from collections import OrderedDict
from ipaddress import IPv4Network
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

try:
    from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
    from cloudshell.shell.core.driver_context import (InitCommandContext, ResourceCommandContext,
                                                      AutoLoadCommandContext, AutoLoadAttribute,
                                                      AutoLoadResource, AutoLoadDetails)

except:
    pass

from jcloudlabs.helper.jcl_context import JclContext
from jcloudlabs.helper.jcl_git import jcl_git
from jcloudlabs.util.logger.jcl_logger import JclLogger


class cmp_metadata(object):
    def __init__(self, context=None):
        self.owner_user = context.reservation.owner_user
        self.name = context.resource.name

        self.id = context.reservation.reservation_id
        if (self.owner_user is not None) and (self.id is not None):
            #  Initializing JCL Logger
            self.logger = JclLogger(self.owner_user, self.id, self.name)
        else:
            raise Exception("compute-metadata: Incorrect reservation info for: init-logger")

        self.cntxt = JclContext(context=context, name=context.resource.name)
        self.session = self.cntxt.session
        self.TopologyName = self.session.GetReservationDetails(self.id).ReservationDescription.Name
        try:
            self.res_desp = self.session.GetReservationDetails(self.id).ReservationDescription
        except:
            self.logger.logError('API call getreservationdetails failed')

        self.connection = self.res_desp.RequestedRoutesInfo
        self.topo_resources = self.res_desp.TopologiesReservedResources
        self.resource_list = self.res_desp.Resources

        self.JUNIPER_USERNAME = 'root'
        self.JUNIPER_PASSWORD = 'Juniper!1'
        self.LINUX_USERNAME = 'root'
        self.LINUX_PASSWORD = 'Juniper!1'
        self.SPIRENT_USERNAME = 'jcluser'
        self.SPIRENT_PASSWORD = 'Juniper!1'
        self.SPIRENT_REST_PORT = 80
        self.IXIA_USERNAME = 'jcluser'
        self.IXIA_PASSWORD = 'Juniper!1'
        self.IXIA_REST_PORT = 11009
        self.HelperVM_CONFIG_FILENAME = 'HelperVM_config.json'
        self.RESOURCE_GW_ADDRESS = '100.123.0.1'
        self.RESOURCE_NETMASK = '16'

    def compute_reservation_metadata(self, api_access_token=None):
        reservation_dict = OrderedDict()
        reservation_dict[str('reservation_user')] = self.owner_user
        reservation_dict[str('topology_name')] = self.TopologyName
        if api_access_token is None:
            self.cntxt.logError('api_access_token is not passed in')
        elif api_access_token == 'null':
            pass
        else:
            reservation_dict[str('api_access_token')] = api_access_token
        data = yaml.dump(dict(reservation_dict), default_flow_style=False)
        self.cntxt.logInfo('reservation metadata: ' + data)
        # tag = 'RSV'
        # self.hpcntxt.write_to_file(data=data, tag=tag)
        # self.hpcntxt.write_file_to_resource(tag=tag)
        return data

    def compute_connection_metadata(self):
        topology_dict = dict()
        topology_dict[str('topo')] = dict()

        for connect in self.connection:
            source_resource_name = connect.Source.split('/')[0]
            dest_resource_name = connect.Target.split('/')[0]
            topology_dict[str('topo')][source_resource_name] = dict()
            topology_dict[str('topo')][dest_resource_name] = dict()
        for connect in self.connection:
            source_resource_name = connect.Source.split('/')[0]
            source_port_name = connect.Source.split('/')[-1]
            source_port_alias = self._get_alias_name()[connect.Source]
            dest_resource_name = connect.Target.split('/')[0]
            dest_port_name = connect.Target.split('/')[-1]

            dest_port_alias = self._get_alias_name()[connect.Target]
            # topology_dict[str('topo')][source_resource_name] = dict()
            topology_dict[str('topo')][source_resource_name][source_port_alias] = OrderedDict()
            self.logger.logInfo(
                'source_resource_name: {source_resource_name}, source_port_name: {source_port_name}'.format(
                    source_resource_name=source_resource_name, source_port_name=source_port_name))
            # session.WriteMessageToReservationOutput(context.reservation.reservation_id, connect.Source)
            topology_dict[str('topo')][source_resource_name][source_port_alias][
                str('name')] = source_port_name.replace('_', '/')
            topology_dict[str('topo')][source_resource_name][source_port_alias][
                str('peer')] = dest_resource_name
            topology_dict[str('topo')][source_resource_name][source_port_alias][
                str('pport')] = dest_port_alias
            topology_dict[str('topo')][source_resource_name][source_port_alias] = dict(
                topology_dict[str('topo')][source_resource_name][source_port_alias])
            # the other direction
            self.logger.logInfo(
                'target_resource_name: {target_resource_name}, target_port_name: {target_port_name}'.format(
                    target_resource_name=dest_resource_name, target_port_name=dest_port_name))
            topology_dict[str('topo')][dest_resource_name][dest_port_alias] = OrderedDict()
            topology_dict[str('topo')][dest_resource_name][dest_port_alias][
                str('name')] = dest_port_name.replace('_', '/')
            topology_dict[str('topo')][dest_resource_name][dest_port_alias][
                str('peer')] = source_resource_name
            topology_dict[str('topo')][dest_resource_name][dest_port_alias][
                str('pport')] = source_port_alias
            topology_dict[str('topo')][dest_resource_name][dest_port_alias] = dict(
                topology_dict[str('topo')][dest_resource_name][dest_port_alias])
        topo_yaml = yaml.dump(topology_dict, default_flow_style=False)
        self.logger.logInfo('connection metadata: ' + topo_yaml)
        return topo_yaml

    def compute_nvvxlan_metadata(self):
        topology_dict = dict()
        topology_dict['vxlans'] = dict()
        vxlan_pool = '100.88.0.0/16'
        subnets = IPv4Network(vxlan_pool.decode('utf-8')).subnets(new_prefix=30)
        vni_id = 4000
        alias_dict = self._get_alias_name()
        for connect in self.connection:
            source_resource_name = connect.Source.split('/')[0]
            source_resmodel = self.session.GetResourceDetails(resourceFullPath=source_resource_name).ResourceModelName
            if not source_resmodel.endswith('NV'):
                self.logger.logDebug(
                    msg='source resource model is %s, thus not assigning ip address to the interface' % source_resmodel)
                continue
            dest_resource_name = connect.Target.split('/')[0]
            dest_resmodel = self.session.GetResourceDetails(resourceFullPath=dest_resource_name).ResourceModelName
            if not dest_resmodel.endswith('NV'):
                self.logger.logDebug(
                    msg='destination resource model is %s, thus not assigning ip address to the interface' % dest_resmodel)
                continue
            source_resalias = alias_dict[source_resource_name]
            dest_resalias = alias_dict[dest_resource_name]
            topology_dict['vxlans'][source_resalias] = dict()
            topology_dict['vxlans'][dest_resalias] = dict()

        for connect, subnet in zip(self.connection, subnets):
            source_resource_name = connect.Source.split('/')[0]

            source_resalias = alias_dict[source_resource_name]
            source_resmodel = self.session.GetResourceDetails(resourceFullPath=source_resource_name).ResourceModelName
            if not source_resmodel.endswith('NV'):
                self.logger.logDebug(
                    msg='source resource model is %s, thus not assigning ip address to the interface' % source_resmodel)
                continue
            source_port_name = connect.Source.split('/')[-1]
            source_port_alias = alias_dict[connect.Source]
            dest_resource_name = connect.Target.split('/')[0]
            dest_resalias = alias_dict[dest_resource_name]
            dest_resmodel = self.session.GetResourceDetails(resourceFullPath=dest_resource_name).ResourceModelName
            if not dest_resmodel.endswith('NV'):
                self.logger.logDebug(
                    msg='destination resource model is %s, thus not assigning ip address to the interface' % dest_resmodel)
                continue

            self.logger.logInfo(msg='IP network to use in connection: %s' % subnet)

            int_netmask = subnet.prefixlen
            available_ip = list(subnet.hosts())
            sourceint_ip = str(available_ip[0])
            destint_ip = str(available_ip[1])

            dest_port_name = connect.Target.split('/')[-1]

            dest_port_alias = self._get_alias_name()[connect.Target]

            topology_dict['vxlans'][source_resalias][source_port_alias] = OrderedDict()
            self.logger.logDebug(
                'source_resource_name: {source_resource_name}, source_port_name: {source_port_name}'.format(
                    source_resource_name=source_resource_name, source_port_name=source_port_name))
            # topology_dict['vxlans'][source_resalias][source_port_alias][
            #     str('name')] = source_port_name.replace('_', '/')
            topology_dict['vxlans'][source_resalias][source_port_alias][
                str('peer')] = dest_resalias
            topology_dict['vxlans'][source_resalias][source_port_alias][
                str('pport')] = dest_port_alias
            # vxlan specific
            topology_dict['vxlans'][source_resalias][source_port_alias]['vni'] = vni_id
            topology_dict['vxlans'][source_resalias][source_port_alias]['ip'] = sourceint_ip + '/' + str(int_netmask)
            topology_dict['vxlans'][source_resalias][source_port_alias]['peerip'] = destint_ip
            if source_resmodel == 'Linux_NV':
                sourceint_num = source_port_alias[-1]
            else:
                sourceint_num = str(int(source_port_alias[-1]) + 1)
            topology_dict['vxlans'][source_resalias][source_port_alias]['bridge'] = 'br' + sourceint_num
            topology_dict['vxlans'][source_resalias][source_port_alias]['hostint'] = 'eth' + sourceint_num

            topology_dict['vxlans'][source_resalias][source_port_alias] = dict(
                topology_dict['vxlans'][source_resalias][source_port_alias])
            # the other direction
            self.logger.logDebug(
                'target_resource_name: {target_resource_name}, target_port_name: {target_port_name}'.format(
                    target_resource_name=dest_resource_name, target_port_name=dest_port_name))
            topology_dict['vxlans'][dest_resalias][dest_port_alias] = OrderedDict()
            # topology_dict['vxlans'][dest_resalias][dest_port_alias][
            #     str('name')] = dest_port_name.replace('_', '/')
            topology_dict['vxlans'][dest_resalias][dest_port_alias][
                str('peer')] = source_resalias
            topology_dict['vxlans'][dest_resalias][dest_port_alias][
                str('pport')] = source_port_alias

            # vxlan specific
            topology_dict['vxlans'][dest_resalias][dest_port_alias]['vni'] = vni_id
            topology_dict['vxlans'][dest_resalias][dest_port_alias]['ip'] = destint_ip + '/' + str(int_netmask)
            topology_dict['vxlans'][dest_resalias][dest_port_alias]['peerip'] = sourceint_ip
            if dest_resmodel == 'Linux_NV':
                destint_num = dest_port_alias[-1]
            else:
                destint_num = str(int(dest_port_alias[-1]) + 1)
            topology_dict['vxlans'][dest_resalias][dest_port_alias]['bridge'] = 'br' + destint_num
            topology_dict['vxlans'][dest_resalias][dest_port_alias]['hostint'] = 'eth' + destint_num

            topology_dict['vxlans'][dest_resalias][dest_port_alias] = dict(
                topology_dict['vxlans'][dest_resalias][dest_port_alias])

            vni_id += 1
        vxlan_yaml = yaml.dump(topology_dict, default_flow_style=False)
        self.logger.logInfo('vxlan metadata: ' + vxlan_yaml)

        return vxlan_yaml

    def compute_baremetal_metadata(self):
        iscsi_dict = dict()
        iscsi_dict[str('iscsivol')] = dict()
        services = self.cntxt.services
        volume_service_list = list()
        for svs in services:
            if svs.ServiceName == 'iSCSI_Volume_Service':
                volume_dict = dict()
                volume_dict['Alias'] = svs.Alias
                iscsi_dict[str('iscsivol')][svs.Alias] = dict()
                attributes = svs.Attributes
                for attr in attributes:
                    volume_dict[attr.Name] = attr.Value
                volume_service_list.append(volume_dict)
        for volume_svs in volume_service_list:
            svs_alias = volume_svs['Alias']
            iscsi_dict[str('iscsivol')][svs_alias]['portal_address'] = volume_svs['iSCSI Portal Address']
            iscsi_dict[str('iscsivol')][svs_alias]['target_iqn'] = volume_svs['iSCSI Target IQN']
            iscsi_dict[str('iscsivol')][svs_alias]['chap_user'] = volume_svs['iSCSI CHAP User']
            iscsi_dict[str('iscsivol')][svs_alias]['chap_secret'] = volume_svs['iSCSI CHAP Secret']
        iscsi_yaml = yaml.dump(iscsi_dict, default_flow_style=False)
        self.logger.logInfo('iscsi volume metadata: ' + iscsi_yaml)
        return iscsi_yaml

    def compute_inventory_metadata(self, context):
        self.logger.logInfo("INFO: computing inventory metadata", console=True)
        # Start inventory
        Config = ConfigParser.ConfigParser(allow_no_value=True)
        Config.optionxform = str
        Config.add_section('all:children')
        file_content = None
        # first, try to get the json file from infra-git
        # file_content = self.get_from_git('HelperVM_config.json', context)
        jclgit = jcl_git(cntxt=self.cntxt, git_res_name='Infra_Git')
        file_content = jclgit.get_from_git(project_name='JCL/configs/HelperVM', filename='HelperVM_config.json')[0]
        if file_content is None or not file_content:
            self.logger.logError("failed to get helpervm_config.json from Infra-git")
            raise Exception("failed to get Helpervm_config.json from Infra-git")

        self.logger.logInfo("INFO: Reading HelperVM_config.json from infra-git", console=True)
        resources_config = json.loads(file_content)["devices"]

        resources_config_dict = self._get_resmodel_key_dict(resources_config)
        self.logger.logInfo(resources_config_dict, console=True)
        # Get Spirent Port list
        spirent_port_dict = self._get_spirent_ports()
        # Get Alias name dict
        alias_dict = self._get_alias_name()
        for resource in self.resource_list:
            if resource.ResourceModelName != 'vRIG' and resource.ResourceFamilyName != 'Port' \
                    and resources_config_dict.has_key(resource.ResourceModelName):
                Config.set('all:children', resources_config_dict[resource.ResourceModelName]['parent'])
                section_name = resources_config_dict[resource.ResourceModelName]['parent'] + ':children'
                resource_attribute_names = resources_config_dict[str(resource.ResourceModelName)]["attributes"]

                attribute_dict = dict()
                for attribute in resource_attribute_names:
                    try:
                        attribute_dict[str(attribute.replace(' ', ''))] = self.session.GetAttributeValue(
                            resourceFullPath=resource.Name,
                            attributeName=attribute).Value.replace(' ', '_')
                    except Exception:
                        self.logger.logDebug('No such attribute {attribute} for {resource}'
                                             .format(attribute=attribute, resource=resource.Name))
                self.logger.logInfo(attribute_dict)
                try:
                    Config.add_section(section_name)
                except ConfigParser.DuplicateSectionError:
                    self.logger.logInfo('Section already exists, not adding', console=True)
                model_name = '_' + resource.ResourceModelName
                Config.set(section_name, model_name)
                model_sec_name = model_name + ':children'
                try:
                    Config.add_section(model_sec_name)
                except ConfigParser.DuplicateSectionError:
                    self.logger.logInfo('Section already exists, not adding', console=True)
                try:
                    alias_name = alias_dict[resource.Name]
                except KeyError:
                    self.logger.logWarn('cannot find alias name for resource {}'.format(resource.Name), console=True)
                    alias_name = resource.Name

                # Config.set(model_sec_name, alias_name)
                # attribute list
                attr_ini = ''
                # juniper resource specific attribute
                if resources_config_dict[resource.ResourceModelName]['parent'] == 'juniper':
                    attr_ini = attr_ini + 'junos_host=' + resource.FullAddress + ' ' + 'mgmt_sub_gw=' + '100.123.0.1' \
                               + ' ' + 'mgmt_sub_mask=' + '16' + ' aliase=' + alias_name + ' '

                    # vxlan NV specific
                    if resource.ResourceModelName.endswith('NV'):
                        try:
                            Config.add_section('nvhost:children')
                        except ConfigParser.DuplicateSectionError:
                            self.logger.logDebug('Section already exists, not adding', console=True)
                        Config.set('nvhost:children', alias_name)

                # spirent resource specific attribute
                if resources_config_dict[resource.ResourceModelName]['parent'] == 'spirent':
                    if resource.ResourceModelName == 'STC_Chassis':
                        for k, v in spirent_port_dict.items():
                            if v['class'] == 'virtual':
                                continue
                            Config.set(model_sec_name, k)
                            spirent_port_sec = k
                            try:
                                Config.add_section(spirent_port_sec)
                            except ConfigParser.DuplicateSectionError:
                                self.logger.logInfo('Section %s already exists, not adding' % spirent_port_sec,
                                                    console=True)
                            spirent_attr = attr_ini + ' spirent_ctrl=' + resource.FullAddress + ' portaddress=' + \
                                           v['address'] + ' aliase=' + v['aliase']
                            Config.set(spirent_port_sec, v['name'] + ' ' + spirent_attr)
                        continue
                    else:
                        attr_ini = attr_ini + ' spirent_ctrl=' + resource.FullAddress + ' portaddress=' + \
                                   spirent_port_dict[alias_name]['address'] + ' aliase=' + \
                                   spirent_port_dict[alias_name]['aliase']
                # ixia resource specific attribute
                if resources_config_dict[resource.ResourceModelName]['parent'] == 'ixia':
                    attr_ini = attr_ini + ' portaddress=' + resource.FullAddress
                # linux resource specific attribute
                if resources_config_dict[resource.ResourceModelName]['parent'] == 'linux':
                    attr_ini = attr_ini + ' ansible_ssh_host=' + resource.FullAddress
                    # vxlan NV specific
                    if resource.ResourceModelName.endswith('NV'):
                        try:
                            Config.add_section('nvhost:children')
                        except ConfigParser.DuplicateSectionError:
                            self.logger.logDebug('Section already exists, not adding', console=True)
                        Config.set('nvhost:children', alias_name)
                        attr_ini = attr_ini + ' aliase=' + alias_name + ' '

                        # cyberflood resource specific attribute
                if resources_config_dict[resource.ResourceModelName]['parent'] == 'cyberflood':
                    attr_ini = attr_ini + ' ansible_ssh_host=' + resource.FullAddress

                # baremetal resource specific attrbute
                if resources_config_dict[resource.ResourceModelName]['parent'] == 'baremetal':
                    storage_requested = self.get_storagevolume_requested_from_blueprint(resource_name=resource.Name)

                    if storage_requested and \
                            (storage_requested['OS'].lower() == 'linux' or storage_requested['OS'].lower() == 'esxi'):
                        attr_ini = attr_ini + ' ansible_ssh_host=' + resource.FullAddress + \
                                   ' ansible_ssh_pass=Juniper!1'
                    if storage_requested:
                        if storage_requested['OS'].lower() == 'esxi':
                            attr_ini = attr_ini + ' storage_volume=' + storage_requested['Name'] + \
                                       '  OS=' + storage_requested['OS'] + ' netmask=255.255.255.0'
                        else:
                            attr_ini = attr_ini + ' storage_volume=' + storage_requested['Name'] + ' MountPoint=' \
                                       + storage_requested['MountPoint'] + '  OS=' + storage_requested['OS'] \
                                       + ' netmask=255.255.255.0'
                        try:
                            Config.add_section('iscsi:children')
                        except ConfigParser.DuplicateSectionError:
                            self.logger.logDebug('Section already exists, not adding', console=True)
                        Config.set('iscsi:children', alias_name)
                for attribute in attribute_dict.iterkeys():
                    if attribute_dict[str(attribute)] != '':
                        attr_ini = attr_ini + ' ' + str(attribute) + '=' + str(attribute_dict[str(attribute)]) + '  '
                # if abstract resource
                # if alias_name != resource.Name:
                self.logger.logInfo("INFO: attr_ini: " + str(attr_ini), console=True)
                Config.set(model_sec_name, alias_name)
                alias_section = alias_name
                try:
                    Config.add_section(alias_section)
                    # else:
                    #     Config.set(model_sec_name, str(resource.Name) + ' ' + attr_ini)
                except ConfigParser.DuplicateSectionError:
                    self.logger.logInfo('Section already exists, not adding', console=True)
                Config.set(alias_section, str(resource.Name) + ' ' + attr_ini)

        Config.write(open('hosts', 'w'))
        f = open('hosts', 'r')
        data = f.read()
        self.logger.logInfo('Inventory File: \n' + data, console=True)
        return data

    def compute_hosts_metadata(self, original_data):
        # Get /etc/hosts file from HelperVM
        jclgit = jcl_git(cntxt=self.cntxt, git_res_name='Infra_Git')
        file_content = jclgit.get_from_git(project_name='JCL/configs/HelperVM', filename='HelperVM_config.json')[0]
        if file_content is None or not file_content:
            self.logger.logError("failed to get helpervm_config.json from Infra-git")
            raise Exception("failed to get Helpervm_config.json from Infra-git")

        self.logger.logInfo("INFO: Reading HelperVM_config.json from infra-git", console=True)
        resources_config = json.loads(file_content)["devices"]
        # resources_config_dict example { "vMX" : { "parent": "juniper", "attributes": ["Console Address", "Static Routes", "Management IP"] }}
        resources_config_dict = self._get_resmodel_key_dict(resources_config)
        self.logger.logInfo(resources_config_dict)
        alias_dict = self._get_alias_name()
        # try:
        #     self.hpcntxt.get_file_from_resource(tag=tag)
        # except Exception:
        #     self.logger.logError('Failed to get hosts file from {resource}'.format(resource=self.name), console=True)
        data = original_data
        for resource in self.resource_list:
            if resource.ResourceModelName != 'vRIG' and resource.ResourceFamilyName != 'Port' and resources_config_dict.has_key(
                    resource.ResourceModelName):
                try:
                    dns_entry = resource.FullAddress + '  ' + resource.Name + ' ' + alias_dict[resource.Name] + '\n'
                except KeyError:
                    self.logger.logInfo(
                        'cannot find alias name for resource {} , no alias name, should be concrete resource'.format(
                            resource.Name))
                    dns_entry = resource.FullAddress + '  ' + resource.Name + '\n'
                # with open(self.hpcntxt.HelperVM_NameResolution_FILE, "a") as hostsfile:
                #     hostsfile.write(dns_entry)
                data = data + dns_entry
        self.logger.logInfo('data generated for /etc/hosts file: %s' % data)
        return data

    def compute_juniper_metadata(self):
        juniper_dict = OrderedDict()
        juniper_dict[str('junos_username')] = self.JUNIPER_USERNAME
        juniper_dict[str('junos_passwd')] = self.JUNIPER_PASSWORD
        data = yaml.dump(dict(juniper_dict), default_flow_style=False)
        self.logger.logInfo('juniper metadata: ' + data)
        return data

    def compute_juniper_publicip_metadata(self):
        self.logger.logInfo("INFO: computing juniper public ip metadata in juno devices.", console=True)

        publicip_dict = dict()
        publicip_dict[str('publicip')] = dict()

        # TODO
        # ref: IntGwy email.py
        result, msg = self.cntxt.check_special_resources()
        self.cntxt.get_relevant_resources()
        ##########################################
        for res in self.cntxt.resources:
            if res.ResourceModelName == 'PublicAddress':
                res_ParentName = res.Name.split('/')[0]
                res_Name = res.Name.split('/')[1]
                res_Address = res.FullAddress.split('/')[1]
                res_Alias = self.cntxt.ResourceAlias[res_ParentName]
                # res_Alias.replace("-", "--", 1)
                key_str = res_Alias + "_" + res_Name
                # juniper_dict[key_str] = res_Address
                publicip_dict[str('publicip')][key_str] = res_Address
                self.logger.logInfo("INFO: found PublicAddress: parent alias=" + res_Alias + ", name=")

        ##########################################

        # data = yaml.dump(dict(juniper_dict), default_flow_style=False)
        data = yaml.dump(dict(publicip_dict), default_flow_style=False)
        self.logger.logInfo('juniper public ip metadata: ' + str(data), console=True)
        return data

    def compute_linux_metadata(self):
        linux_dict = OrderedDict()
        linux_dict[str('ansible_ssh_user')] = self.LINUX_USERNAME
        linux_dict[str('ansible_ssh_pass')] = self.LINUX_PASSWORD
        data = yaml.dump(dict(linux_dict), default_flow_style=False)
        self.logger.logInfo('linux metadata: ' + data)
        return data

    def compute_spirent_metadata(self):
        lab_server = self._get_spirent_lab_server()
        spirent_dict = OrderedDict()
        spirent_dict[str('ansible_ssh_user')] = self.SPIRENT_USERNAME
        spirent_dict[str('ansible_ssh_pass')] = self.SPIRENT_PASSWORD
        spirent_dict[str('ansible_ssh_host')] = lab_server
        spirent_dict[str('rest_port')] = self.SPIRENT_REST_PORT
        data = yaml.dump(dict(spirent_dict), default_flow_style=False)
        self.logger.logInfo('Spirent metadata: ' + data)
        return data

    def compute_cyberflood_metadata(self):

        cyberflood_dict = OrderedDict()
        cyberflood_dict[str('ansible_ssh_user')] = 'jcluser@juniper.net'
        cyberflood_dict[str('ansible_ssh_pass')] = 'Juniper!1'

        cyberflood_dict[str('ansible_ssh_host')] = '127.0.0.1'
        data = yaml.dump(dict(cyberflood_dict), default_flow_style=False)
        self.logger.logInfo('Cyberflood metadata: ' + data)
        return data

    def compute_ixia_metadata(self):
        ixia_rest_address = self._get_ixia_rest_server()
        ixia_dict = OrderedDict()
        ixia_dict[str('ansible_ssh_user')] = self.IXIA_USERNAME
        ixia_dict[str('ansible_ssh_pass')] = self.IXIA_PASSWORD
        ixia_dict[str('ansible_ssh_host')] = ixia_rest_address
        ixia_dict[str('rest_port')] = self.IXIA_REST_PORT
        ixia_dict[str('rest_body')] = self._generate_ixia_rest_body()
        data = yaml.dump(dict(ixia_dict), default_flow_style=False).replace("'", '')
        self.logger.logInfo('REST BODY: ' + data)
        return data

    def compute_inventory_csv(self):
        """
        Function to compute inventory csv device csv file under /etc/toby
        :return:
        """
        jclgit = jcl_git(cntxt=self.cntxt, git_res_name='Infra_Git')
        file_content = jclgit.get_from_git(project_name='JCL/configs/HelperVM', filename='HelperVM_config.json')[0]
        if file_content is None or not file_content:
            self.logger.logError("failed to get helpervm_config.json from Infra-git")
            raise Exception("failed to get Helpervm_config.json from Infra-git")

        self.logger.logInfo("INFO: Reading HelperVM_config.json from infra-git", console=True)
        resources_config = json.loads(file_content)["devices"]
        resources_config_dict = self._get_resmodel_key_dict(resources_config)
        self.logger.logInfo(resources_config_dict)
        system_id_index = 1
        with open('device.csv', 'wb') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',')
            csvwriter.writerow(['system_id', 'system-name', 'make', 'model', 'dual-re', 'mgmt-ip', 'role', 'domain'])
            for resource in self.resource_list:
                if resource.ResourceModelName != 'vRIG' \
                        and resource.ResourceFamilyName != 'Port' \
                        and resources_config_dict.has_key(resource.ResourceModelName):
                    csvwriter.writerow(
                        [system_id_index, resource.Name, resources_config_dict[resource.ResourceModelName]['parent'],
                         resource.ResourceModelName, 'False', resource.FullAddress, 'CORE', 'cloudlabs.juniper.net'])
                    system_id_index = system_id_index + 1
        f = open('device.csv', 'r')
        data = f.read()
        self.logger.logInfo('device csv: ' + data)
        return data

    def compute_connection_csv(self):
        """
        Function to compute connection csv device csv file under /etc/toby
        :return:
        """
        connection_type = 'ge'
        connection_tags = '1g'
        link_index = 1
        with open('connection.csv', 'wb') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',')
            csvwriter.writerow(['link', 'connection_type', 'a_end', 'a_end_ifd', 'b_end', 'b_end_ifd', 'notes', 'tags'])
            for connect in self.connection:
                source_resource_name = connect.Source.split('/')[0]
                dest_resource_name = connect.Target.split('/')[0]
                source_port_name = connect.Source.split('/')[-1].replace('_', '/')
                dest_port_name = connect.Target.split('/')[-1].replace('_', '/')
                if 'ge' in source_port_name or 'ge' in dest_port_name:
                    connection_type = 'ge'
                    connection_tags = '1g'
                elif 'xe' in source_port_name or 'xe' in dest_port_name:
                    connection_type = 'xe'
                    connection_tags = '10g'
                elif 'et' in source_port_name or 'et' in dest_port_name:
                    connection_type = 'et'
                    connection_tags = '40g'
                csvwriter.writerow([link_index, connection_type, source_resource_name, source_port_name,
                                    dest_resource_name, dest_port_name, '', connection_tags])
                link_index = link_index + 1
                # csvwriter.writerow([link_index, connection_type, dest_resource_name, dest_port_name,
                #                     source_resource_name, source_port_name, '', connection_tags])
                # link_index = link_index + 1

        f = open('connection.csv', 'r')
        data = f.read()
        self.logger.logInfo('connection csv: ' + data)
        return data

    def _get_alias_name(self):
        resource_alias = dict()
        for topo_res in self.topo_resources:
            resource_alias[str(topo_res.Name)] = topo_res.Alias.replace(' ', '_')
        return resource_alias

    def _get_json(self, file_name):
        """
        Private function to get dictionary from json file
        :param file_name:
        :return:
        """
        # Workaround to save json to file in utf-8 without BOM in Python
        # s_config = HELPERVM_CONFIG.encode('utf-8')
        # # file_name.encode('utf-8')
        # with open(file_name, 'wb') as fptr:
        #     # session.WriteMessageToReservationOutput(self.reservationId, fptr.read())
        #     fptr.write(s_config)
        with open(file_name, 'r') as fptr:
            helper_data = json.load(fptr)
            print helper_data
            self.logger.logInfo('Finishing convert json')
            self.logger.logInfo(helper_data)
        # resources_config = helper_data["devices"]
        return helper_data

    def _get_spirent_ports(self):
        """
        Private function to compute Spirent port list, if no spirent, return OrderedDict()
        :return:
        """
        port_list_dict = dict()
        for resource in self.resource_list:
            if resource.ResourceModelName == 'SpirentVTC':
                children = self.session.GetResourceDetails(resourceFullPath=resource.Name).ChildResources
                for child in children:
                    aliase_name = ''
                    child_detail_dict = dict()
                    if child.ResourceModelName == 'Spirent Virtual Port':
                        child_detail_dict[str('name')] = child.Name
                        child_detail_dict[str('address')] = child.FullAddress
                        aliase_name = self._get_alias_name()[resource.Name] + '/' + \
                                      self._get_alias_name()[child.Name]
                        child_detail_dict[str('aliase')] = aliase_name
                    elif child.ResourceModelName == 'Virtual Blade':
                        grand_children = child.ChildResources
                        for grand_child in grand_children:
                            if grand_child.ResourceModelName == 'Spirent Virtual Port':
                                child_detail_dict[
                                    str('name')] = grand_child.Name
                                child_detail_dict[str(
                                    'address')] = grand_child.FullAddress
                                # aliase_name = self._get_alias_name(context)[resource.Name] + '/' + \
                                #               self._get_alias_name(context)[grand_child.Name]
                                aliase_name = self._get_alias_name()[resource.Name]
                                child_detail_dict['aliase'] = aliase_name
                                child_detail_dict['class'] = 'virtual'
                    print child_detail_dict
                    port_list_dict[aliase_name] = child_detail_dict

            elif resource.ResourceModelName == 'Generic Traffic Generator Port' and \
                    'STC_Chassis' in resource.FolderFullPath:
                port_detail_dict = dict()
                # Prepare for future physical
                aliase_name = self._get_alias_name()[resource.Name.split('/')[0]] + '/' \
                              + self._get_alias_name()[resource.Name]
                port_detail_dict['name'] = resource.Name
                port_detail_dict['address'] = resource.FullAddress
                port_detail_dict['aliase'] = aliase_name
                port_detail_dict['class'] = 'physical'
                port_list_dict[aliase_name] = port_detail_dict
        port_list_sort_dict = OrderedDict(sorted(port_list_dict.iteritems()))
        for index, (key, value) in enumerate(port_list_sort_dict.items()):
            port_list_sort_dict[key]['aliase'] = 'port' + str(index + 1)
        return port_list_sort_dict

    def _get_resmodel_key_dict(self, resources_config):
        """
        Private function to get a dictionary with ResourceModelName as the key
        :param resources_config: dictionary
        :return:
        """
        resources_config_dict = dict()
        for res_conf in resources_config:
            # temp_config_dict example: { "parent": "juniper", "attributes": ["Console Address", "Static Routes", "Management IP"] }
            temp_config_dict = dict()
            temp_config_dict = res_conf["resource"]
            temp_key = res_conf["resource"]["ResourceModelName"]
            resources_config_dict[str(temp_key)] = dict()
            resources_config_dict[str(temp_key)] = temp_config_dict
        self.logger.logInfo(resources_config_dict)
        return resources_config_dict

    def _get_spirent_lab_server(self):
        """
        Private function to get IP of Spirent Lab Server
        :return:
        """
        lab_server = None
        tag = 0
        for resource in self.resource_list:
            # self.logger.logInfo(resource.Name, True)
            if resource.ResourceModelName == 'SpirentLabSrv':
                self.logger.logInfo('Spirent LabSrv name: %s' % resource.Name, True)
                try:
                    tag = 1
                    lab_server = resource.FullAddress
                    break
                except Exception as e:
                    self.logger.logError('Failed to get Spirent Lab Server IP with exception %s' % e)
                    lab_server = '127.0.0.1'
        if tag == 0:
            lab_server = '127.0.0.1'
        return lab_server

    def _get_ixia_rest_server(self):
        """
        Private function to get IP of Ixia GUI IP
        :return:
        """
        rest_server = None
        tag = 0
        self.logger.logInfo('Start to get Ixia REST Server address', True)
        for resource in self.resource_list:
            if resource.ResourceModelName == 'IxiaGUI':
                try:
                    tag = 1
                    rest_server = resource.FullAddress
                    self.logger.logInfo('Got Ixia REST Server address %s' % rest_server)
                    break
                except Exception as e:
                    self.logger.logError('Failed to get Ixia GUI IP with Exception %s' % e)
                    rest_server = '127.0.0.1'
        if tag == 0:
            rest_server = '127.0.0.1'
        return rest_server

    def _generate_ixia_rest_body(self):
        """
        Private function to prepare ixia rest body to assignports
        eg:
        {"arg1": [{"arg1": '100.123.37.1', "arg2": '1', "arg3": '1'}, {"arg1": '100.123.37.0', "arg2": '1', "arg3": '1'}], "arg2": [], "arg3": ['http://{{ ansible_ssh_host }}:{{ rest_port }}/api/v1/sessions/1/ixnetwork/vport/1', 'http://{{ ansible_ssh_host }}:{{ rest_port }}/api/v1/sessions/1/ixnetwork/vport/2'], "arg4": 'true'}
        :param context:
        :return:
        """
        rest_body = ''
        rest_body_dict = dict()
        ixia_port_dict = self._get_ixia_ports()
        port_address_list = []
        vport_list = []
        self.logger.logInfo(self.logger, 'Getting ixia Ports dictionary with its alias name')
        self.logger.logInfo(self.logger, ixia_port_dict)
        if len(ixia_port_dict) > 0:
            ixia_rest_server = self._get_ixia_rest_server()
            for index, (key, value) in enumerate(ixia_port_dict.items()):
                port_dict = dict()
                port_address = ixia_port_dict[key]['address'].split('/')
                print port_address
                port_dict["arg1"] = port_address[0]
                port_dict["arg2"] = port_address[1]
                port_dict["arg3"] = port_address[2]
                self.logger.logInfo(self.logger, 'Generated arg1')
                self.logger.logInfo(self.logger, port_dict)
                port_address_list.append(port_dict)
                # vport handle generation
                handle_number = str(index + 1)
                vport_list.append('http://' + ixia_rest_server + ':' + str(
                    11009) + '/api/v1/sessions/1/ixnetwork/vport/' + handle_number)
            self.logger.logInfo('arg3: ', True)
            self.logger.logInfo(port_address_list, True)
            self.logger.logInfo('vport handle: ', True)
            self.logger.logInfo(vport_list, True)
            rest_body_dict["arg1"] = port_address_list
            rest_body_dict["arg2"] = []
            rest_body_dict["arg3"] = vport_list
            rest_body_dict["arg4"] = 'true'
            self.logger.logInfo('rest_body_dict: ', True)
            self.logger.logInfo(rest_body_dict, True)
            # Convert dictionary to json representation
            rest_body = json.dumps(rest_body_dict, sort_keys=True)
            self.logger.logInfo(rest_body, True)
        return rest_body

    def _get_ixia_ports(self):
        """
        Private function to compute Ixia port list
        :return:
        """
        port_list_dict = dict()
        for resource in self.resource_list:
            if resource.ResourceModelName == 'IxiaVTA':
                children = self.session.GetResourceDetails(resourceFullPath=resource.Name).ChildResources
                for child in children:
                    aliase_name = ''
                    child_detail_dict = dict()
                    if child.ResourceModelName == 'Ixia Virtual Port':
                        child_detail_dict[str('name')] = child.Name
                        child_detail_dict[str('address')] = child.FullAddress
                        aliase_name = self._get_alias_name()[resource.Name] + '/' + \
                                      self._get_alias_name()[child.Name]
                        child_detail_dict[str('aliase')] = aliase_name
                    elif child.ResourceModelName == 'Virtual Blade':
                        grand_children = child.ChildResources
                        for grand_child in grand_children:
                            if grand_child.ResourceModelName == 'Ixia Virtual Port':
                                child_detail_dict[
                                    str('name')] = grand_child.Name
                                child_detail_dict[str(
                                    'address')] = grand_child.FullAddress
                                # aliase_name = self._get_alias_name(context)[resource.Name] + '/' + \
                                #               self._get_alias_name(context)[grand_child.Name]
                                aliase_name = self._get_alias_name()[resource.Name]
                                child_detail_dict[str('aliase')] = aliase_name
                    # print child_detail_dict
                    port_list_dict[aliase_name] = child_detail_dict

            elif resource.ResourceModelName == 'Ixia':
                # Prepare for future physical
                pass
        port_list_sort_dict = OrderedDict(sorted(port_list_dict.iteritems()))
        return port_list_sort_dict

    def get_storagevolume_requested_from_blueprint(self, resource_name=None, storage_requested=None):
        func_name = "get_version_requested_from_blueprint()"
        self.cntxt.get_relevant_resources()
        alias_name = self.cntxt.ResourceAlias[resource_name]
        input_value = ''
        if storage_requested is not None or storage_requested:
            self.cntxt.logInfo('Getting Image Requested value from UserInput', console=True)
            input_value = storage_requested
        else:
            self.cntxt.logInfo('Getting Storage Volume value from AdditionalInfoInputs', console=True)
            self.cntxt.get_inputs()
            additional_info_inputs = self.cntxt.AdditionalInfoInputs

            if additional_info_inputs is not None and len(additional_info_inputs) != 0:
                for inputs in additional_info_inputs:
                    if inputs.ResourceName == alias_name and inputs.ParamName == 'Storage Volume 1':
                        input_value = inputs.Value
        if input_value:
            self.cntxt.logInfo('Storage volume Requested value: %s' % input_value, console=True, output=True)
            if input_value.lower() == 'any' or input_value.lower() == '[any]':
                self.cntxt.logInfo('Storage Volume Requested is set as any...', console=True, output=True)
                storage_requested = dict()
            else:
                input_value = input_value.replace(' ', '')
                try:
                    storage_requested = dict(map(lambda x: x.split('='), input_value.split(';')))
                except ValueError as ex:
                    self.cntxt.logError('failed to convert the value to a dictionary with exception %s' % ex,
                                        console=True)
                    msg = 'Incorrect format set for Storage Volume on abstract resource {alias_name} as {input_value}' \
                        .format(alias_name=alias_name, input_value=input_value)
                    self.cntxt.logError(msg=msg, console=True, output=True)
                    storage_requested = dict()
                else:
                    if 'Name' not in storage_requested or not storage_requested['Name']:
                        msg = 'Name is not defined in Storage Volume on abstract resource {alias_name} as {input_value}' \
                            .format(alias_name=alias_name, input_value=input_value)
                        self.cntxt.logError(msg=msg, console=True, output=True)
                        return dict()

                    if 'OS' not in storage_requested or not storage_requested['OS']:
                        msg = 'OS is not defined in Storage Volume on abstract resource {alias_name} as {input_value}' \
                            .format(alias_name=alias_name, input_value=input_value)
                        self.cntxt.logError(msg=msg, console=True, output=True)
                        return dict()

                    if storage_requested['OS'].lower() != 'esxi' and \
                            'MountPoint' not in storage_requested:
                        msg = 'MountPoint is not defined in Storage Volume on abstract resource ' \
                              '{alias_name} as {input_value}'.format(alias_name=alias_name, input_value=input_value)
                        self.cntxt.logError(msg=msg, console=True, output=True)
                        return dict()
                    elif storage_requested['OS'].lower() != 'esxi' and 'MountPoint' in storage_requested \
                            and not storage_requested['MountPoint']:
                        msg = 'MountPoint is not defined in Storage Volume on abstract resource ' \
                              '{alias_name} as {input_value}'.format(alias_name=alias_name, input_value=input_value)
                        self.cntxt.logError(msg=msg, console=True, output=True)
                        return dict()

        else:
            self.cntxt.logDebug('input value is empty...', console=True)
            return dict()
        return storage_requested
