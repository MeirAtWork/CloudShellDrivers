from __future__ import unicode_literals
from tenacity import *
import time
from jcloudlabs.helper.AutoBotCmd import AutoBotCmd
from jcloudlabs.util.logger.jcl_logger import logInfo, logDebug, logError, logWarn
from emails import send_email_demo_cmd
from git_context import GitContext
from metadata_composer import cmp_metadata


def resource_specific_begin(cntxt):
    """Run the initialization actions specific for this resource, not found in the parent class method.
    Function is called from sandbox_action, for 'begin' phase

    Args:
        cntxt:

    Returns:

    """
    funcName = 'res_specific_begin'
    startTime = cntxt.logDebugCmdStart(funcName=funcName, console=True)
    cntxt.logInfo("Starting sandbox_action_begin", output=True, console=True)
    gitcntxt = GitContext(cntxt=cntxt)
    try:
        if cntxt.domain_name.lower() == 'vLabs'.lower():
            cntxt.logInfo("Domain vLAB", console=True)
            cntxt.logDebug('Start to decide on the GitLab username')
            _grant_git_username(cntxt=cntxt, gitcntxt=gitcntxt)
            # gitcntxt.generate_public_key()
            cntxt.logDebug('Start to generate public key on HelperVM')
            generate_public_key(cntxt)
            cntxt.logDebug('Start to add public key to GitLab user account')
            gitcntxt.add_key_to_git_user()
            # gitcntxt.git_clone_to_resource()
            cntxt.logDebug('Start to add metadata file to HelperVM')
            write_metadata_to_helpervm(cntxt=cntxt)
            cntxt.logDebug('Start to change HelperVM hostname for resource')
            _change_hostname(cntxt)

        else:
            cntxt.logDebug('Start to create an account for user if does not have one before')
            gitcntxt.create_git_user()
            cntxt.logDebug('Start to generate public key on HelperVM')
            generate_public_key(cntxt)
            cntxt.logDebug('Start to add public key to GitLab user account')
            gitcntxt.add_key_to_git_user()
            cntxt.logDebug('Start to pull templatizer project to HelperVM')
            gitcntxt.git_clone_to_resource()
            cntxt.logDebug('Start to add metadata file to HelperVM')
            write_metadata_to_helpervm(cntxt=cntxt, api_access_token=gitcntxt.create_impersonate_key())
            cntxt.logDebug('Start to change HelperVM hostname for resource')
            _change_hostname(cntxt)
    except Exception as ex:
        msg = "Exception encountered while preparing resource {}. Message was: {}".format(cntxt.name, str(ex))
        emailsubj = 'URGENT: Error occurred in sandbox_action_begin at %s' % cntxt.name
        details_for_admins = 'Exception encountered %s' % ex
        cntxt.logDebugCmdAbort(funcName=funcName, msg=msg, emailsubj=emailsubj, details_for_admins=details_for_admins)
    cmd_result = True
    cntxt.logDebugCmdEnd(funcName=funcName, cmd_result=cmd_result, startTime=startTime, console=True)
    return


def resource_specific_config(cntxt):
    """Run the initialization actions specific for this resource, not found in the parent class method.
    Function is called from sandbox_action, for 'config' phase

    Args:
        cntxt:

    Returns:

    """
    funcName = 'res_specific_config'
    startTime = cntxt.logDebugCmdStart(funcName=funcName, console=True)

    cmdresult = True

    cntxt.logDebugCmdEnd(funcName=funcName, cmd_result=cmdresult, startTime=startTime, console=True)
    return cmdresult


def resource_specific_startup(cntxt):
    """Run the initialization actions specific for this resource, not found in the parent class method.
    Function is called from sandbox_action, for 'startup' phase

    Args:
        cntxt:

    Returns:

    """
    funcName = 'res_specific_startup'
    startTime = cntxt.logDebugCmdStart(funcName=funcName, console=True)

    # specific code here
    cmdresult = True

    cntxt.logDebugCmdEnd(funcName=funcName, cmd_result=cmdresult, startTime=startTime, console=True)
    return cmdresult


def resource_specific_cleanup(cntxt):
    """Run the completion actions specific for this resource, not found in the parent class method.
    Function is called from sandbox_action, for 'cleanup' phase

    Args:
        cntxt:

    Returns:

    """
    funcName = 'res_specific_cleanup'
    startTime = cntxt.logDebugCmdStart(funcName=funcName, console=True)

    # specific code here
    cmdresult = True

    cntxt.logDebugCmdEnd(funcName=funcName, cmd_result=cmdresult, startTime=startTime, console=True)
    return cmdresult


def resource_specific_end(cntxt):
    """
    Run the completion actions specific for this resource, not found in the parent class method.
    Function is called from sandbox_action, for 'end' phase

    Args:
        cntxt:

    Returns:

    """
    funcName = 'res_specific_end'
    startTime = cntxt.logDebugCmdStart(funcName=funcName, console=True)
    try:
        gitcntxt = GitContext(cntxt=cntxt)
        # if statement is temporary
        if cntxt.domain_name.lower() == 'vLabs'.lower():
            cntxt.logInfo("Domain vLAB", console=True)
            _grant_git_username(cntxt=cntxt, gitcntxt=gitcntxt)
        gitcntxt.del_key_from_git_user()
        set_online_status(cntxt, status="Offline")
    except Exception as ex:
        msg = "Exception encountered while ending resource {}. Message was: {}".format(cntxt.name, str(ex))
        emailsubj = 'Error occurred in sandbox_action_end at %s' % cntxt.name
        details_for_admins = 'Exception encountered %s' % ex
        cntxt.logDebugCmdAbort(funcName=funcName, msg=msg, emailsubj=emailsubj, details_for_admins=details_for_admins)
    cmdresult = True
    cntxt.logDebugCmdEnd(funcName=funcName, cmd_result=cmdresult, startTime=startTime, console=True)
    return cmdresult


def resource_specific_startover1(cntxt, version_requested=None):
    """
    Run the restart actions specific for this resource, not found in the parent class method.
    Function is called from sandbox_action, for 'startover' phase and before call to the parent class method

    Args:
        cntxt:
        version_requested:
    Returns:

    """
    funcName = 'resource_specific_startover1'
    startTime = cntxt.logDebugCmdStart(funcName=funcName, console=True)
    try:
        if cntxt.domain_name.lower() == 'vLabs'.lower():
            cntxt.logInfo("Domain vLAB", console=True)
            cntxt.logDebug("Start to prepare git context...")
            gitcntxt = GitContext(cntxt=cntxt)
            cntxt.logInfo('Start to compute the GitLab username for vlabs users')
            _grant_git_username(cntxt=cntxt, gitcntxt=gitcntxt)
            cntxt.logInfo('Start to delete the ssh key from vlab GitLab user account')
            gitcntxt.del_key_from_git_user()
            cntxt.logInfo('Generating ssh key on HelperVM...')
            generate_public_key(cntxt)
            cntxt.logInfo('Adding the generated ssh key to GitLab user account and name it as the name of HelperVM')
            gitcntxt.add_key_to_git_user()
            # gitcntxt.git_clone_to_resource()
            cntxt.logInfo('adding sandbox/resource related metadata to HelperVM')
            write_metadata_to_helpervm(cntxt=cntxt)
            cntxt.logInfo('Give HelperVM its hostname')
            _change_hostname(cntxt)

        else:
            cntxt.logInfo('non-vlab domain...')
            cntxt.logDebug("Start to prepare git context...")
            gitcntxt = GitContext(cntxt=cntxt)
            # self._grant_git_username(context, gitcntxt)
            cntxt.logInfo('Start to create GitLab account for the user if the user does not have one')
            gitcntxt.create_git_user()
            cntxt.logInfo('Generating ssh key on HelperVM...')
            generate_public_key(cntxt)
            cntxt.logInfo('Adding the generated ssh key to GitLab user account and name it as the name of HelperVM')
            gitcntxt.add_key_to_git_user()
            cntxt.logInfo('Pulling JCL_Ansible_Playbook project to HelperVM')
            gitcntxt.git_clone_to_resource()
            cntxt.logInfo('adding sandbox/resource related metadata to HelperVM')
            write_metadata_to_helpervm(cntxt=cntxt, api_access_token=gitcntxt.create_impersonate_key())
            cntxt.logInfo('Change hostname for HelperVM')
            _change_hostname(cntxt)
    except Exception as ex:
        msg = "Exception encountered while preparing resource {}. Message was: {}".format(cntxt.name, str(ex))
        emailsubj = 'URGENT: Error occurred in startover1 at %s' % cntxt.name
        details_for_admins = 'Exception encountered %s' % ex
        cntxt.logDebugCmdAbort(funcName=funcName, msg=msg, emailsubj=emailsubj, details_for_admins=details_for_admins)
    cmdresult = True
    cntxt.logDebugCmdEnd(funcName=funcName, cmd_result=cmdresult, startTime=startTime, console=True)
    return cmdresult


def resource_specific_startover2(cntxt, version_requested=None):
    """Run the restart actions specific for this resource, not found in the parent class method.
    Function is called from sandbox_action, for 'startover' phase and after call to the parent class method

    Args:
        cntxt:

    Returns:

    """
    funcName = 'resource_specific_startover2'
    startTime = cntxt.logDebugCmdStart(funcName=funcName, console=True)
    resource_specific_begin(cntxt)
    cmdresult = True
    cntxt.logDebugCmdEnd(funcName=funcName, cmd_result=cmdresult, startTime=startTime, console=True)
    return cmdresult


def run_demo_command(cntxt, command, timeout, cmddesc=""):
    helpervm_username = cntxt.attributes['User']
    helpervm_password = cntxt.session.DecryptPassword(cntxt.attributes['Password']).Value
    helpervm_act = HelperVM(logger=cntxt.logger,
                            host=cntxt.attributes.get('Public Address Mgt'),
                            port=cntxt.attributes.get('Public Port SSH'),
                            username=helpervm_username,
                            password=helpervm_password)
    if cmddesc:
        cntxt.logInfo('run demo command cmddesc: %s' % cmddesc)
    try:
        begin_time = time.time()
        stdout, stderr, status = helpervm_act.run_command(command=command, timeout=timeout)
        cntxt.logInfo('send command to %s HelperVM' % command)
        time_elapsed = time.time() - begin_time
        suppress = False
        email_settings = cntxt.get_gi_email_settings(key="HelperVM", default_value="yes")
        if email_settings and email_settings.lower().strip() == "no":
            suppress = True

        send_email_demo_cmd(cntxt, command=command, timeout=timeout, cmddesc=cmddesc, stdout=stdout, stderr=stderr,
                            status=status, time_elapsed=time_elapsed, suppress=suppress)

    except Exception as ex:
        cntxt.logError('Error when sending command to HelperVM with Exception %s' % ex)
        raise ex
    return


def generate_public_key(cntxt):
    helpervm_username = cntxt.attributes['User']
    helpervm_password = cntxt.session.DecryptPassword(cntxt.attributes['Password']).Value
    helpervm_act = HelperVM(logger=cntxt.logger,
                            host=cntxt.attributes.get('Public Address Mgt'),
                            port=cntxt.attributes.get('Public Port SSH'),
                            username=helpervm_username,
                            password=helpervm_password)
    generatePublicKeyCommand = 'ssh-keygen -q -t rsa -N "" -f ~/.ssh/id_rsa <<< y'
    logDebug(cntxt.logger, 'Starting to generate public key on Helpervm with command %s' % generatePublicKeyCommand)
    try:
        helpervm_act.run_command(command=generatePublicKeyCommand, timeout=200)
    except Exception as ex:
        msg = 'failed to generate public key on HelperVM after all retries with Exception %s' % ex
        logError(cntxt.logger, msg)
        raise Exception(ex)
    logDebug(cntxt.logger, 'Starting to get public key from HelperVM')
    try:
        helpervm_act.get_file_from_remote(remote_file='/root/.ssh/id_rsa.pub',
                                          local_file='HelperVM.pub')
    except Exception as ex:
        msg = 'failed to get public key file from remote with exception %s' % ex
        logError(cntxt.logger, msg)
        raise ex


def write_metadata_to_helpervm(cntxt, api_access_token=None):
    metadata_typelist = ['reservation',
                         'inventory',
                         'connection',
                         'juniper',
                         'juniper_publicip',
                         'linux',
                         'spirent',
                         'cyberflood',
                         'ixia',
                         'baremetal',
                         'inv_csv',
                         'connection_csv',
                         'vxlan',
                         'dns']
    for metadata_type in metadata_typelist:
        cntxt.logInfo('start to compute and write metadata type {metadata_type} to HelperVM'
                      .format(metadata_type=metadata_type))
        try:
            _write_metadata(cntxt=cntxt, type=metadata_type, api_access_token=api_access_token)
        except Exception as ex:
            msg = 'exception %s raised when writing metadata to HelperVM' % ex
            cntxt.logError(msg)
            raise ex
    return


def _write_metadata(cntxt, type, api_access_token=None):
    context = cntxt.context
    mtda = cmp_metadata(context)
    if type == 'reservation':
        filename = 'reservation.yaml'
        filepath = '/etc/ansible/group_vars/all/reservation.yaml'
        data = mtda.compute_reservation_metadata(api_access_token=api_access_token)
    elif type == 'inventory':
        filename = 'hosts'
        filepath = '/etc/ansible/hosts'
        data = mtda.compute_inventory_metadata(context=context)
    elif type == 'connection':
        filename = 'topology.yaml'
        filepath = '/etc/ansible/group_vars/all/topology.yaml'
        data = mtda.compute_connection_metadata()
    elif type == 'vxlan':
        filename = 'vxlannv.yaml'
        filepath = '/etc/ansible/group_vars/all/vxlannv.yaml'
        data = mtda.compute_nvvxlan_metadata()
    elif type == 'juniper':
        filename = 'credentials.yaml'
        filepath = '/etc/ansible/group_vars/juniper/credentials.yaml'
        data = mtda.compute_juniper_metadata()
    elif type == 'juniper_publicip':
        filename = 'public_ip.yaml'
        filepath = '/etc/ansible/group_vars/juniper/public_ip.yaml'
        data = mtda.compute_juniper_publicip_metadata()
    elif type == 'linux':
        filename = 'access.yaml'
        filepath = '/etc/ansible/group_vars/linux/access.yaml'
        data = mtda.compute_linux_metadata()
    elif type == 'spirent':
        filename = 'access.yaml'
        filepath = '/etc/ansible/group_vars/spirent/access.yaml'
        data = mtda.compute_spirent_metadata()
    elif type == 'cyberflood':
        filename = 'access.yaml'
        filepath = '/etc/ansible/group_vars/cyberflood/access.yaml'
        data = mtda.compute_cyberflood_metadata()
    elif type == 'ixia':
        filename = 'access.yaml'
        filepath = '/etc/ansible/group_vars/ixia/access.yaml'
        data = mtda.compute_ixia_metadata()
    elif type == 'baremetal':
        filename = 'iscsi.yaml'
        filepath = '/etc/ansible/group_vars/baremetal/iscsi.yaml'
        data = mtda.compute_baremetal_metadata()
    elif type == 'inv_csv':
        filename = 'device.csv'
        filepath = '/etc/toby/device.csv'
        data = mtda.compute_inventory_csv()
    elif type == 'connection_csv':
        filename = 'connection.csv'
        filepath = '/etc/toby/connection.csv'
        data = mtda.compute_connection_csv()
    elif type == 'dns':
        filename = 'hosts'
        filepath = '/etc/hosts'
        helpervm_username = cntxt.attributes['User']
        helpervm_password = cntxt.session.DecryptPassword(cntxt.attributes['Password']).Value
        helpervm_act = HelperVM(logger=cntxt.logger,
                                host=cntxt.attributes.get('Public Address Mgt'),
                                port=cntxt.attributes.get('Public Port SSH'),
                                username=helpervm_username,
                                password=helpervm_password)
        logDebug(cntxt.logger, 'Starting to get /etc/hosts from HelperVM')
        try:
            helpervm_act.get_file_from_remote(remote_file=filepath,
                                              local_file=filename)
        except Exception as ex:
            msg = 'failed to get /etc/hosts file from remote with exception %s' % ex
            logError(cntxt.logger, msg)
            raise ex
        original_data = ''
        with open(filename, 'r') as file:
            original_data = file.read()
        data = mtda.compute_hosts_metadata(original_data)
    else:
        cntxt.logInfo('metadata type not supported, not doing anything')
        return
    if data is not None:
        _write_to_file(data=data, filename=filename)
    else:
        cntxt.logDebug('data is a NoneType, will grant empty string to it...')
        _write_to_file(data='', filename=filename)
    cntxt.logDebug('starting an instance of helpervm to transfer metadata type %s' % type)
    helpervm_username = cntxt.attributes['User']
    helpervm_password = cntxt.session.DecryptPassword(cntxt.attributes['Password']).Value
    helpervm_act = HelperVM(logger=cntxt.logger,
                            host=cntxt.attributes.get('Public Address Mgt'),
                            port=cntxt.attributes.get('Public Port SSH'),
                            username=helpervm_username,
                            password=helpervm_password)
    try:
        helpervm_act.transfer_file(src_file=filename, dst_file=filepath)
        cntxt.logInfo('file transferred to {filepath} on HelperVM'.format(filepath=filepath))
    except Exception as ex:
        cntxt.logError('Error when transferring file to HelperVM with Exception %s' % ex)
        raise ex
    return


def _grant_git_username(cntxt, gitcntxt):
    """
    Private function to grant git username and email to user that does not have a GitLab account
    :param cntxt:
    :param gitcntxt:
    :return:
    """
    if not gitcntxt.find_git_user():
        # User does not exist on GitLab Server
        cntxt.logInfo('User does not exist on GitLab Server', console=True)
        if cntxt.domain_name.lower() == 'vLabs'.lower():
            cntxt.logInfo("Domain vLAB", console=True)
            gitcntxt.owner_user = 'vlabuser'
            gitcntxt.user_email = '_vlabs@juniper.net'
        else:
            cntxt.logInfo("domains non-vlab", console=True)
            gitcntxt.owner_user = 'jcl-test'
            gitcntxt.user_email = 'JCL-Devops@juniper.net'
    return


def _write_to_file(data, filename):
    _writefile = open(filename, "w")
    try:
        _writefile.write(data)
    except Exception as ex:
        raise ex
    finally:
        _writefile.close()
    return


def _change_hostname(cntxt):
    """
    Private function to change resource hostname
    :param cntxt:
    :return:
    """
    host_name = cntxt.name + '.cloudlabs.juniper.net'
    change_name_cmd = 'echo ' + host_name + ' > /etc/hostname; reboot'
    helpervm_username = cntxt.attributes['User']
    helpervm_password = cntxt.session.DecryptPassword(cntxt.attributes['Password']).Value
    helpervm_act = HelperVM(logger=cntxt.logger,
                            host=cntxt.attributes.get('Public Address Mgt'),
                            port=cntxt.attributes.get('Public Port SSH'),
                            username=helpervm_username,
                            password=helpervm_password)
    try:
        helpervm_act.run_command(command=change_name_cmd, timeout=120)
        cntxt.logInfo('send command to change hostname of HelperVM')
    except Exception as ex:
        cntxt.logError('Error when sending command to HelperVM with Exception %s' % ex)
        raise ex
    return


def set_online_status(cntxt=None, status=None):
    ts = time.strftime('%Y-%m-%d - %H:%M:%S', time.gmtime())
    cntxt.session.SetResourceLiveStatus(cntxt.name, status, ts)


class HelperVM(object):
    def __init__(self, **kwargs):
        self.host = None
        self.port = None
        self.username = None
        self.password = None
        self.logger = None
        for key in ('logger', 'host', 'port', 'username', 'password', 'res_id', 'name', 'power_port', 'session'):
            if key in kwargs:
                setattr(self, key, kwargs[key])
        if self.logger is None:
            raise Exception('logger is not provided')
        if self.host is None or self.port is None or self.username is None or self.password is None:
            logError(self.logger, 'HelperVM information is not provided...')
            raise Exception('HelperVM information is not provided(host or port or username or password)')
        logDebug(self.logger, '__init__ is done')

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=32), reraise=True)
    def run_command(self, command, timeout=60):
        connection = AutoBotCmd(hostname=self.host,
                                username=self.username,
                                password=self.password,
                                port=self.port)
        try:
            connection.connect()
            connection.keep_alive()
            logInfo(self.logger, 'starting to run command on remote host')
            stdout, stderr, status = connection.exec_command(command=command, timeout=timeout)
            return stdout, stderr, status
        except Exception as ex:
            msg = 'Error opening connection and exec command on HelperVM with exception %s' % ex
            logError(self.logger, msg)
            raise Exception(msg)
        finally:
            if connection is not None:
                logInfo(self.logger, 'closing the connection to remote host...')
                connection.close()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=32), reraise=True)
    def get_file_from_remote(self, remote_file, local_file):
        connection = AutoBotCmd(hostname=self.host,
                                username=self.username,
                                password=self.password,
                                port=self.port)
        try:
            connection.connect()
            connection.keep_alive()
            logInfo(self.logger, 'start to get file from remote host to local file path')
            connection.get_file(remote_file_path=remote_file,
                                local_file_path=local_file)
        except Exception as ex:
            logError(self.logger, 'Error opening connection and exec command on HelperVM with exception %s' % ex)
        finally:
            if connection is not None:
                logInfo(self.logger, 'closing the connection to remote host...')
                connection.close()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=32), reraise=True)
    def transfer_file(self, src_file, dst_file):
        connection = AutoBotCmd(hostname=self.host,
                                username=self.username,
                                password=self.password,
                                port=self.port)
        try:
            connection.connect()
            connection.keep_alive()
            logInfo(self.logger, 'start to transfer file to remote host from local file path')
            connection.transfer_file(local_file_path=src_file, remote_file_path=dst_file)
        except Exception as ex:
            logError(self.logger, 'Error opening connection and exec command on HelperVM with exception %s' % ex)
        finally:
            if connection is not None:
                logInfo(self.logger, 'closing the connection to remote host...')
                connection.close()
