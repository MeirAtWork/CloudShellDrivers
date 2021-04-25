from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, ResourceCommandContext
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext



# Version of driver.py: 3.2.0


class Resource_Driver():

    def __init__(self):
        """ctor must be without arguments, it is created with reflection at run time

        Args:

        Returns:

        """
        pass

    def initialize(self, context):
        """Initialize the driver session, this function is called every time a new instance of the driver is created
            This is a good place to load and cache the driver configuration, initiate sessions etc.


        Args:
            context (InitCommandContext): the context the command runs on

        Returns:

        """
        pass

    def sandbox_action(self, context, action=None, version_requested=None, sequence=None):
        """Configure resource for a specific phase of a sandbox

        Args:
            context:
            action (str): Has one of these values: begin/config/startup/cleanup/end/other/custom
            version_requested (str): Optional name of requested version (VM template or Junos release)
            sequence (str): Optional command sequence string

        Returns:

        """
        func_name = 'sandbox_action'
        cmd_name = "Sandbox-action '{}' ".format(action)

        return
        

    def startover(self, context, version_requested=None):
        """Re-init the resource (VMs) and re-connect network interfaces (sub-resources)

        Args:
            context:
            version_requested (str): name of the version (template) used to re-build the resource. If empty string submitted, it will use the same Template VM as the existing VM

        Returns:

        """
        func_name = 'startover'
        cmd_name = "Start-Over, with Version Requested => '{}'".format(str(version_requested))
        
        return

    def connect_interface(self, context, interface_name, network_name, connected):
        """Connect interface (sub-resource) to the port-group

        Args:
            context:
            interface_name (str): Name of the sub-resource
            network_name (str): Name of the port-group
            connected (str): Allowed values on/off. Indicates if interface is connected to the port-group or not

        Returns:

        """
        
        return

    def connect_interface_group(self, context, action_list=None):
        """Connect interface multiple interfaces (group) to the port-groups (VLANs)

        Args:
            context:
            action_list (str): Encoded list of interfaces, port-groups and connection statuses

        Returns:

        """
        
        return

    def power_on(self, context):
        """Power ON the virtual resource

        Args:
            context:

        Returns:
        """
        
        return

    def power_off(self, context):
        """Power OFF the virtual resource

        Args:
            context:

        Returns:
        """
        
        
        return

    def power_cycle(self, context):
        """Power Cycle the virtual resource

        Args:
            context:

        Returns:
        """
        
        return

    def enable_vmconsole_access(self, context):
        """Generate VM console access token and update the resource attribute

        Args:
            context:

        Returns:
        """
        
        
        return

    def health_check(self, context, timeout=None, retries=None):
        """Test Out of Band Management access to resource. Ste OnLine status on the resource (visible in canvas)

        Args:
            context:
            timeout (str): Time between two attempts
            retries (str): Number of attempts

        Returns:

        """
        
        return

    def oobmgt_connect(self, context):
        """(re)Connect Management interface(s) to the Out of Band Management Network

        Args:
            context:

        Returns:

        """
        
        return

    def oobmgt_disconnect(self, context):
        """Disconnect Management interface(s) from the Out of Band Management Network

        Args:
            context:

        Returns:

        """
        
        return

    def add_license(self, context, license_key=None):
        """Connect to the resource over SSH and add license key

        Args:
            context:
            license_key (str):

        Returns:

        """
        
        return

    def list_versions(self, context):
        """List all existing resource versions, VM templates

        Args:
            context:

        Returns:

        """
        
        return

    def save_version(self, context, short_version_name=None, name_space=None):
        """Save existing resource VMs as a new version (template). VMs must be in PowerOFF state.

        Args:
            context:
            short_version_name (str): Short name of the version. Complete name will be created by prepending owner's username and dash characters
            name_space (str): Indicates if this is in user or public (global) name space. If in user name space, the name will be prepended with usr_username-

        Returns:

        """
        
        return

    def list_snapshots(self, context):
        """List all existing snapshots in the Output window

        Args:
            context:

        Returns:

        """
        
        return

    def create_snapshot(self, context, snapshot_name=None):
        """Create (take) snapshot on all VM(s) of this resource

        Args:
            context:
            snapshot_name (str): Name of the new snapshot

        Returns:

        """
        
        return

    def revert_snapshot(self, context, snapshot_name=None, auto_poweron=None):
        """Revert VMs of this resource to an existing snapshot, and (optionally) PowerON the resource

        Args:
            context:
            snapshot_name (str): Name of the existing snapshot to revert VMs to
            auto_poweron (str): Should resource be powered-on after reverting to the snapshot? Values: y/Y/N/n

        Returns:
        """
        
        return

    def delete_snapshot(self, context, snapshot_name=None):
        """Delete an existing snapshot of the VMs of this resource

        Args:
            context:
            snapshot_name (str): Name of an existing snapshot

        Returns:

        """
        
        return

    def setvm_cddrive(self, context, cdrom_image=None):
        """Set (connect) VM's CD-DRIVE to ISO Image

        Args:
            context:
            cdrom_image (str): Name of the CD-ROM image

        Returns:

        """
        
        return

    def setvm_ram_size(self, context, ram_size=None):
        """Set VM's RAM size

        Args:
            context:
            ram_size (str): new RAM size in GB

        Returns:

        """
        
        return

    def setvm_disk_size(self, context, disk_id=None, disk_size=None):
        """Set VM's Disk size

        Args:
            context:
            disk_id (str): Disk ID, number as string; 1 for the first disk
            disk_size (str): new Disk size in GB

        Returns:

        """
        
        return

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files

        """
        pass

    # resource specific commands
    def cmd_run_startup_command(self, context):
        func_name = 'cmd_run_startup_command'
        
        cmd_name = 'Run Startup command'
        cmd_result = False
        command_type = 'startup'
        
        return

    def cmd_run_cleanup_command(self, context, batch, number):
        return "the batch is " + batch + " and the number is " + number

    def run_demo_command(self, context, command, timeout, cmddesc=""):
        """
        Function to run command on resource
        :param context:
        :param command:
        :param timeout: default is 60s
        :param cmddesc: default is empty string
        :return:
        """
        func_name = 'cmd_run_demo_command'
        cmd_name = "Demo command"
        
        return
