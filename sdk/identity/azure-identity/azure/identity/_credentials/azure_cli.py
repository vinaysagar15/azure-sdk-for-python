# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from datetime import datetime
import json
import time

from subprocess import run, PIPE
import six

from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError

from .._internal import _scopes_to_resource

_CLI_NOT_INSTALLED_ERR = "Azure CLI not installed"
_CLI_LOGIN_ERR = "ERROR: Please run 'az login' to setup account.\r\n"

_COMMAND_LINE = "az account get-access-token --output json --resource {}"


class AzureCliCredential(object):
    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        resource = _scopes_to_resource(*scopes)
        command = _COMMAND_LINE.format(resource)

        try:
            get_access_token_stdout = self._run_command(command)
            get_access_token_object = json.loads(get_access_token_stdout)
            access_token = get_access_token_object["accessToken"]
        except ClientAuthenticationError:
            raise
        except Exception as e:
            raise ClientAuthenticationError(repr(e))

        expires_on = int(
            (
                datetime.strptime(get_access_token_object["expiresOn"], "%Y-%m-%d %H:%M:%S.%f") - datetime.now()
            ).total_seconds()
            + time.time()
        )

        return AccessToken(access_token, expires_on)

    def _run_command(self, command):
        proc = run(command, shell=True, stderr=PIPE, stdout=PIPE, timeout=10)
        return_code = proc.returncode
        stdout = six.ensure_str(proc.stdout)
        stderr = six.ensure_str(proc.stderr)
        if return_code == 127 or (return_code == 1 and "not recognized as" in stderr):
            raise ClientAuthenticationError(self._CLI_NOT_INSTALLED_ERR)
        elif return_code == 1:
            raise ClientAuthenticationError(self._CLI_LOGIN_ERR)

        return stdout
