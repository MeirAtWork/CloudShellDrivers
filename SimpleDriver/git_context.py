#!/usr/bin/env python
import requests
from jcloudlabs.helper.AutoBotCmd import AutoBotCmd


class GitContext(object):
    def __init__(self, cntxt=None):
        self.session = cntxt.session
        self.id = cntxt.id

        self.name = cntxt.name
        self.owner_user = cntxt.owner_user
        self.logger = cntxt.logger
        self.user_email = cntxt.owner_email
        self.host = cntxt.attributes.get('Public Address Mgt')
        self.port = cntxt.attributes.get('Public Port SSH')
        self.username = cntxt.attributes['User']
        self.password = self.session.DecryptPassword(cntxt.attributes['Password']).Value

        self.GIT_SERVER_ADDRESS = 'https://git.cloudlabs.juniper.net'
        self.GIT_ADMIN_TOKEN = 'NGZk_SUxdx7szh7imgx9'
        self.GITCLONECMD = 'git clone git@git.cloudlabs.juniper.net:JCL/JCL_Ansible_Playbooks.git'
        self.GeneratePublicKeyCommand = 'ssh-keygen -q -t rsa -N "" -f ~/.ssh/id_rsa'
        self.PUBLIC_KEY_REMOTE_LOCATION = '/root/.ssh/id_rsa.pub'
        self.PUBLIC_KEY_LOCAL_LOCATION = 'HelperVM.pub'

    def create_git_user(self):
        url = self.GIT_SERVER_ADDRESS + '/api/v4/users?private_token=' + self.GIT_ADMIN_TOKEN
        self.logger.logInfo('Git Add user HTTP POST Request starting ' + url, True)
        payload = dict()
        payload[str('email')] = self.user_email
        payload[str('reset_password')] = 'true'
        payload[str('username')] = self.owner_user
        payload[str('name')] = self.owner_user
        payload[str('skip_confirmation')] = 'true'

        if '@' in self.owner_user:
            self.logger.logInfo('username contains @, Partner, processing username before proceeding')
            username = self.owner_user.replace('@', '_at_', 1)
            payload[str('username')] = username
            payload[str('name')] = username
            self.logger.logInfo('username: ' + username)
        self.logger.logInfo(payload)
        try:
            r = requests.post(url=url, data=payload, verify=False)
        except requests.exceptions.ConnectionError:
            raise Exception(
                'Git Server not reachable from Infra during create user Request, please connect JCL-Support')
        except Exception as e:
            self.logger.logError(e, True)
        # url = GIT_SERVER_ADDRESS + '/api/v4/users?search=chenx@juniper.net&private_token=' + GIT_ADMIN_TOKEN
        #
        # r = requests.get(url=url)
        try:
            return_json = r.json()
            print return_json
            self.logger.logInfo(return_json)
        except ValueError:
            self.logger.logError(ValueError)
        if r.status_code == 201:
            self.logger.logInfo('User Account created on Git Server git.cloudlabs.juniper.net')
            self.session.WriteMessageToReservationOutput(self.id,
                                                         'Created Git Account for user {username}, email {email}'
                                                         .format(
                                                             username=self.owner_user, email=self.user_email))
        elif r.status_code == 409:
            self.logger.logInfo('Email has already taken {email}'.format(email=self.user_email))
            url = self.GIT_SERVER_ADDRESS + '/api/v4/users?search=' + \
                self.user_email + '&private_token=' + self.GIT_ADMIN_TOKEN
            try:
                r = requests.get(url=url, verify=False)
            except requests.exceptions.ConnectionError:
                raise Exception('Git Server not reachable from Infra, please connect JCL-Support')
            except Exception as e:
                self.logger.logError(e, True)

            registed_username = r.json()[0]['username']

            self.logger.logInfo('Email {email} has already been registered with username {username}, continue'
                                .format(email=self.user_email, username=self.owner_user), console=True)
        else:
            self.logger.logInfo(r.status_code, True)
        return

    def add_key_to_git_user(self):
        """
        Private function to add SSH key to user's git account
        :return:
        """
        url = self.GIT_SERVER_ADDRESS + '/api/v4/users?search=' + self.user_email \
            + '&private_token=' + self.GIT_ADMIN_TOKEN
        self.logger.logInfo('Starting to add SSH key to current Git user')
        self.logger.logInfo('REST URL: ' + url, True)
        # Get Git user id
        r = requests.get(url=url, verify=False)
        if not r.json():
            self.logger.logError('User %s not found in GitLab' % self.user_email)
            raise Exception('User %s not found in GitLab' % self.user_email)
        user_id = r.json()[0]['id']
        url = self.GIT_SERVER_ADDRESS + '/api/v4/users/' + str(user_id) + '/keys?private_token=' + self.GIT_ADMIN_TOKEN
        payload = dict()
        payload[str('title')] = self.name
        try:
            key = open(self.PUBLIC_KEY_LOCAL_LOCATION, 'rb')

        except IOError:
            self.logger.logError('Failed to read from file with exception, No such file or directory')
        except Exception as e:
            self.logger.logError('Failed to read file with exception ' + str(e))
        payload[str('key')] = key.read()
        self.logger.logInfo('REST URL: ' + url, True)
        r = requests.post(url=url, data=payload, verify=False)
        self.logger.logInfo('Add SSH key to git user HTTP request result'+str(r.status_code))
        return

    def git_clone_to_resource(self):
        """
        Function to clone JCL_ansible_playbooks from git.cloudlabs.juniper.net
        :return:
        """
        if self.port is not None and self.host is not None:
            try:
                cmd_run = AutoBotCmd(hostname=self.host, username=self.username, password=self.password, port=self.port)
                cmd_run.connect()
                cmd_run.keep_alive()
                stdout, strerr, status = cmd_run.exec_command(self.GITCLONECMD)
                self.logger.logInfo('command output: ' + stdout)
                cmd_run.close()
            except Exception as e:
                self.logger.logInfo(e)
                raise Exception(
                    'Connection timeout with resource {resource}, git clone failed, please check its connectivity'
                    .format(resource=self.name))
        else:
            self.logger.logError('host and port of {resource} not defined'.format(resource=self.name))
        return

    def create_impersonate_key(self):
        """
        Function ro create impersonate token
        :return:
        """
        url = self.GIT_SERVER_ADDRESS + '/api/v4/users?search=' + self.user_email \
            + '&private_token=' + self.GIT_ADMIN_TOKEN
        self.logger.logInfo('USER_EMAIL:\n')
        self.logger.logInfo(self.user_email)
        self.logger.logInfo('URL:\n')
        self.logger.logInfo(url)
        try:
            r = requests.get(url=url, verify=False)
            user_id = r.json()[0]['id']
            print user_id
            self.logger.logInfo('Starting to create impersonate key')
            url = self.GIT_SERVER_ADDRESS + '/api/v4/users/' + str(
                user_id) + '/impersonation_tokens?private_token=' + self.GIT_ADMIN_TOKEN
            payload = dict()
            payload[str('name')] = self.name + '-' + self.owner_user + 'token'
            payload[str('scopes[]')] = 'api'
            r = requests.post(url=url, data=payload, verify=False)
            status_code = r.status_code
            if status_code == 201:
                self.logger.logInfo(
                    'Successfully create impersonate token for user {user}'.format(user=self.user_email))
                return str(r.json()['token'])
            else:
                self.logger.logError(
                    'Cannot create impersonate token for user {user}, error message: {error}'.format(
                        user=self.user_email,
                        error=r.json()))
        except Exception as e:
            self.logger.logError('\nEXCEPTION:\n')
            self.logger.logError(e)
            raise e
        return

    def generate_public_key(self):
        """
        Private function to generate public key on resource, and then get the public key
        :return:
        """
        if self.host is not None and self.port is not None:
            self.logger.logInfo(
                'start run command on {host} : {port} with {username} , {password}'.format(host=self.host,
                                                                                           port=self.port,
                                                                                           username=self.username,
                                                                                           password=self.password))
            try:
                cmd_run = AutoBotCmd(hostname=self.host, username=self.username, password=self.password, port=self.port)
                cmd_run.connect()
                cmd_run.keep_alive()
                self.logger.logInfo('Starting to generate public key on HelperVM {resource_name}'
                                    .format(resource_name=self.name))
                self.logger.logInfo('exec command {command}'.format(command=self.GeneratePublicKeyCommand))
                cmd_run.exec_command(self.GeneratePublicKeyCommand, timeout=120)
                # self.logger.logInfo('exec command {command}'.format(command=GeneratePublicKeyCommand))
                cmd_run.get_file(self.PUBLIC_KEY_REMOTE_LOCATION, self.PUBLIC_KEY_LOCAL_LOCATION)
                self.logger.logInfo('Getting public key')
                cmd_run.close()
            except Exception as e:
                self.logger.logInfo(e)
        else:
            self.logger.logError('host and port of {resource} not defined'.format(resource=self.name))
        return

    def del_key_from_git_user(self):
        """
        Private function to delete ssh key from user's git account
        :return:
        """
        self.logger.logInfo('Begin to make rest call to get user id for user %s' % self.user_email)
        url = self.GIT_SERVER_ADDRESS + '/api/v4/users?search=' + self.user_email \
            + '&private_token=' + self.GIT_ADMIN_TOKEN
        r = requests.get(url=url, verify=False)
        if not r.json():
            self.logger.logInfo('user %s does not exist on git server, thus not deleting key, returning' % self.username)
            return
        user_id = r.json()[0]['id']
        # Get key id
        try:
            self.logger.logInfo('Starting to delete ssh key from git user')
            url = self.GIT_SERVER_ADDRESS + '/api/v4/users/' + str(user_id) \
                + '/keys?private_token=' + self.GIT_ADMIN_TOKEN
            r = requests.get(url=url, verify=False)
        except requests.exceptions.ConnectionError:
            self.logger.logInfo('connect timeout with Git Server')
            self.logger.logError('Failed to delete the key, please delete it manually')
        # r = requests.get(url=url, verify=False)
        key_id = None
        if r.status_code == 200:
            key_array = r.json()
            # print key_array
            for key in key_array:
                print key['title']
                if key['title'] == self.name:
                    key_id = key['id']
                    print str(key_id)
                    url = self.GIT_SERVER_ADDRESS + '/api/v4/users/' + str(user_id) + '/keys/' + str(
                        key_id) + '?private_token=' + self.GIT_ADMIN_TOKEN
                    print url
                    r = requests.delete(url=url, verify=False)
        else:
            print r.status_code
            self.logger.logError('Failed to get keys of user')
        # if key_id is not None:
        #     url = GIT_SERVER_ADDRESS + '/api/v4/users/' + str(user_id) + '/keys/' + str(
        #         key_id) + '?private_token=' + GIT_ADMIN_TOKEN
        #     print url
        #     r = requests.delete(url=url)
        #     print r.status_code
        return

    def find_git_user(self):
        """
        Private function to search if the user exist in GitLab Server
        :return:
        """
        # self.owner_user = 'ghouddd'
        url = self.GIT_SERVER_ADDRESS + '/api/v4/users?username=' + \
              self.owner_user + '&private_token=' + self.GIT_ADMIN_TOKEN
        self.logger.logInfo('Starting to search user' + self.owner_user)
        self.logger.logInfo('REST URL: ' + url, True)
        # Verify if exist
        try:
            r = requests.get(url=url, verify=False)
        except requests.exceptions.ConnectionError:
            self.logger.logInfo('connect timeout with Git Server')
            self.logger.logError('Failed to search the user, return false as user does not exist')
            return False
        if r.status_code == 200:
            return_length = len(r.json())
            self.logger.logInfo('length of request result json object ' + str(return_length), console=True)
            if return_length == 0:
                self.logger.logInfo('User does not exist')
                return False
            elif return_length > 0:
                self.logger.logInfo('User has an account on GitLab Server', console=True)
                return True
        else:
            self.logger.logError('Failed to search user with status code as ' + r.status_code, console=True)
        return False
